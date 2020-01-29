#!/usr/local/sbin/charm-env python3
# Copyright 2019 Canonical Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import os
import subprocess
import sys
import traceback

# Load modules from $CHARM_DIR/lib
_path = os.path.dirname(os.path.realpath(__file__))
_lib = os.path.abspath(os.path.join(_path, "../lib"))
_reactive = os.path.abspath(os.path.join(_path, "../reactive"))


def _add_path(path):
    if path not in sys.path:
        sys.path.insert(1, path)


_add_path(_lib)
_add_path(_reactive)

import charms_openstack.charm as charm
import charms.reactive as reactive
import charmhelpers.core as ch_core
import charms_openstack.bus
charms_openstack.bus.discover()


def mysqldump(args):
    """Execute a mysqldump backup.

    Execute mysqldump of the database(s).  The mysqldump action will take
    in the databases action parameter. If the databases parameter is unset all
    databases will be dumped, otherwise only the named databases will be
    dumped. The action will use the basedir action parameter to dump the
    database into the base directory.

    A successful mysqldump backup will set the action results key,
    mysqldump-file, with the full path to the dump file.

    :param args: sys.argv
    :type args: sys.argv
    :side effect: Calls instance.mysqldump
    :returns: This function is called for its side effect
    :rtype: None
    :action param basedir: Base directory to dump the db(s)
    :action param databases: Comma separated string of databases
    :action return:
    """
    basedir = (ch_core.hookenv.action_get("basedir"))
    databases = (ch_core.hookenv.action_get("databases"))

    try:
        with charm.provide_charm_instance() as instance:
            filename = instance.mysqldump(basedir, databases=databases)
        ch_core.hookenv.action_set({
            "mysqldump-file": filename,
            "outcome": "Success"}
        )
    except subprocess.CalledProcessError as e:
        ch_core.hookenv.action_set({
            "output": e.output,
            "return-code": e.returncode,
            "traceback": traceback.format_exc()})
        ch_core.hookenv.action_fail("mysqldump failed")


def cluster_status(args):
    """Display cluster status

    Return cluster.status() as a JSON encoded dictionary

    :param args: sys.argv
    :type args: sys.argv
    :side effect: Calls instance.get_cluster_status
    :returns: This function is called for its side effect
    :rtype: None
    :action return: Dictionary with command output
    """
    with charm.provide_charm_instance() as instance:
        try:
            _status = json.dumps(instance.get_cluster_status())
            ch_core.hookenv.action_set({"cluster-status": _status})
        except subprocess.CalledProcessError as e:
            ch_core.hookenv.action_set({
                "output": e.output,
                "return-code": e.returncode,
                "traceback": traceback.format_exc()})
            ch_core.hookenv.action_fail("Cluster status failed")


def reboot_cluster_from_complete_outage(args):
    """Reboot cluster from complete outage.

    Execute dba.rebootClusterFromCompleteOutage() after the cluster has been
    completely down in an outage. For example in a cold boot scenario. The
    action will also run cluster.rejoinInstance() on its peers to restore the
    cluster completely.

    :param args: sys.argv
    :type args: sys.argv
    :side effect: Calls instance.reboot_cluster_from_complete_outage and
                  instance.rejoin_instance on its peers.
    :returns: This function is called for its side effect
    :rtype: None
    :action return: Dictionary with command output
    """
    # Note: Due to issues/# reactive does not initiate Endpoints during an
    # action execution.  This is here to work around that until the issue is
    # resolved.
    reactive.Endpoint._startup()
    with charm.provide_charm_instance() as instance:
        output = instance.reboot_cluster_from_complete_outage()
        # Add all peers back to the cluster
        for address in instance.cluster_peer_addresses():
            output += instance.rejoin_instance(address)
        instance.assess_status()
    ch_core.hookenv.action_set({
        "output": output,
        "outcome": "Success"}
    )


def rejoin_instance(args):
    """Rejoin a given instance to the cluster.

    In the event an instance is removed from the cluster or fails to
    automatically rejoin, an instance can be rejoined to the cluster by an
    existing cluster member.

    Note: This action must be run on an instance that is already a member of
    the cluster. The action parameter, address, is the addresss of the instance
    that is being joined to the cluster.

    :param args: sys.argv
    :type args: sys.argv
    :side effect: Calls instance.mysqldump
    :returns: This function is called for its side effect
    :rtype: None
    :action param address: String address of the instance to be joined
    :action return: Dictionary with command output
    """
    address = (ch_core.hookenv.action_get("address"))
    with charm.provide_charm_instance() as instance:
        output = instance.rejoin_instance(address)
    ch_core.hookenv.action_set({
        "output": output,
        "outcome": "Success"}
    )


def set_cluster_option(args):
    """Set cluster option.

    Set an option on the InnoDB cluster. Action parameter key is the name of
    the option and action parameter value is the value to be set.

    :param args: sys.argv
    :type args: sys.argv
    :side effect: Calls instance.mysqldump
    :returns: This function is called for its side effect
    :rtype: None
    :action param key: String option name
    :action param value: String option value
    :action return: Dictionary with command output
    """
    key = (ch_core.hookenv.action_get("key"))
    value = (ch_core.hookenv.action_get("value"))
    with charm.provide_charm_instance() as instance:
        output = instance.set_cluster_option(key, value)
    ch_core.hookenv.action_set({
        "output": output,
        "outcome": "Success"}
    )


# A dictionary of all the defined actions to callables (which take
# parsed arguments).
ACTIONS = {"mysqldump": mysqldump, "cluster-status": cluster_status,
           "set-cluster-option": set_cluster_option,
           "reboot-cluster-from-complete-outage":
               reboot_cluster_from_complete_outage,
           "rejoin-instance": rejoin_instance}


def main(args):
    action_name = os.path.basename(args[0])
    try:
        action = ACTIONS[action_name]
    except KeyError:
        return "Action {} undefined".format(action_name)
    else:
        try:
            action(args)
        except Exception as e:
            ch_core.hookenv.action_set({
                "output": e.output.decode("UTF-8"),
                "return-code": e.returncode,
                "traceback": traceback.format_exc()})
            ch_core.hookenv.action_fail(
                "{} action failed.".format(action_name))


if __name__ == "__main__":
    sys.exit(main(sys.argv))