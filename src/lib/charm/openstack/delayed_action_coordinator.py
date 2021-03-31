# Copyright 2021 Canonical Ltd
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 3, as
# published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranties of
# MERCHANTABILITY, SATISFACTORY QUALITY, or FITNESS FOR A PARTICULAR
# PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import json

from charmhelpers.coordinator import BaseCoordinator
from charmhelpers.core import hookenv
from charms import reactive


class DelayedActionCoordinator(BaseCoordinator):
    """A delayed action coordinator.

    Runs an action when the last lock is released.

    Determine the cluster size using goal state, keep track of released locks
    through coordinator-relation-changed hooks, when the released locks count
    is the size of the cluster run the delayed action.
    """

    released_locks_count_key = "coordinator-released-locks-counts"

    def __init__(self, *args, **kwargs):
        """Override BaseCoordinator init.

        Add the _released_locks_counts property
        """
        super().__init__(*args, **kwargs)
        self._released_locks_counts = (
            self.get_released_locks_counts_from_leader_settings())

    def get_released_locks_counts_from_leader_settings(self):
        """Get released locks count from leader settings.

        :returns: Releaed locks counts
        :rtype: dict
        """
        return (json.loads(
                hookenv.leader_get(self.released_locks_count_key) or
                '{}'))

    def increment_released_locks_counts(self, lock):
        """Increment released locks count.

        :param lock: Lock name
        :type lock: str
        :returns: None
        :rtype: None
        """
        if self._released_locks_counts.get(lock) is not None:
            self._released_locks_counts[lock] = (
                self._released_locks_counts[lock] + 1)
        else:
            self._released_locks_counts[lock] = 1

    def set_released_locks_counts_in_leader_settings(self):
        """Set released locks count in leader settings.

        :side effect: Leader set called
        :returns: This function is called for its side effect
        :rtype: None
        """
        hookenv.leader_set(
            {self.released_locks_count_key:
                json.dumps(self._released_locks_counts)})

    def is_last_lock_release(self, lock):
        """Is this the last lock released?

        :param lock: Lock name
        :type lock: str
        :returns: True or False
        :rtype: Bool
        """
        if self._released_locks_counts.get(lock) is None:
            self._released_locks_counts[lock] = 0
            return False
        # Using >= just in case we get into an odd state.
        return self._released_locks_counts[lock] >= self._cluster_size

    def delayed_action(self, lock):
        """Delayed action.

        :param lock: Lock name
        :type lock: str
        :side effect: Set flag called
        :returns: This function is called for its side effect
        :rtype: None
        """
        # TODO It would be good generalize and pass the delayed action in. Due
        # to the current coordinator object instantiation process this will
        # need to be a future change.
        hookenv.log(
            "Coordinated delayed action running.", "DEBUG")
        reactive.set_flag("coordinator-released-{}-lock".format(lock))

    @property
    def _cluster_size(self):
        """Get cluster size.

        Return the number of units in goal state.

        :returns: Cluster size
        :rtype: Int
        """
        return len(hookenv.goal_state()["units"])

    # TODO default_grant is currently duplicated from the SimpleCoordinator
    # class.  However there are circular import failures when attempting to
    # import from charms.coordinator due to the instantiation process.
    def default_grant(self, lock, unit, granted, queue):
        """Grant locks to only one unit at a time, regardless of the lock name.

        This lets us keep separate locks like join and restart,
        while ensuring the operations do not occur on different nodes
        at the same time.
        """
        existing_grants = {k: v for k, v in self.grants.items() if v}

        # Return True if this unit has already been granted any lock.
        if existing_grants.get(unit):
            hookenv.log(
                'Granting {} to {} (existing grants)'.format(lock, unit),
                hookenv.INFO)
            return True

        # Return False if another unit has been granted any lock.
        if existing_grants:
            hookenv.log(
                'Not granting {} to {} (locks held by {})'
                .format(lock, unit, ','.join(existing_grants.keys())),
                hookenv.INFO)
            return False

        # Otherwise, return True if the unit is first in the queue for
        # this named lock.
        if queue[0] == unit:
            hookenv.log(
                'Granting {} to {} (first in queue)'
                .format(lock, unit), hookenv.INFO)
            return True
        else:
            hookenv.log(
                'Not granting {} to {} (not first in queue)'
                .format(lock, unit), hookenv.INFO)
            return False

    def released(self, unit, lock, timestamp):
        """Override BaseCoordinator released.

        Add the is last lock check and delayed action if so.
        """
        super().released(unit, lock, timestamp)
        # Increment the released locks count
        self.increment_released_locks_counts(lock)
        # Check if this is the last coordinated lock release
        if self.is_last_lock_release(lock):
            hookenv.log(
                "Last coordinated lock released for {} running delayed action",
                "DEBUG")
            # Run the delayed action
            self.delayed_action(lock)
            # Reset counts for future coordination
            self._released_locks_counts = {}

    def _save_state(self):
        """Override BaseCoordinator _save_state.

        Add the set released locks count in leader settings.
        """
        self.handle()
        if hookenv.is_leader():
            self.set_released_locks_counts_in_leader_settings()
        super()._save_state()
