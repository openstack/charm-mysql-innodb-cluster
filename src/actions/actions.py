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
from time import gmtime, strftime


# Load modules from $CHARM_DIR/lib
_path = os.path.dirname(os.path.realpath(__file__))
_lib = os.path.abspath(os.path.join(_path, "../lib"))
_reactive = os.path.abspath(os.path.join(_path, "../reactive"))


def _add_path(path):
    if path not in sys.path:
        sys.path.insert(1, path)


_add_path(_lib)
_add_path(_reactive)

from charms.layer import basic
basic.bootstrap_charm_deps()
basic.init_config_states()

import charms_openstack.bus
import charms_openstack.charm as charm
import charm.mysql_innodb_cluster as mysql_innodb_cluster  # noqa

import charmhelpers.core as ch_core

charms_openstack.bus.discover()


def cluster_status(args):
    """Display cluster status

    Return cluster.status() as a JSON encoded dictionary

    :param args: sys.argv
    :type args: sys.argv
    :side effect: Calls instance.get_cluster_status
    :returns: This function is called for its side effect
    :rtype: None
    """
    with charm.provide_charm_instance() as instance:
        try:
            _status = json.dumps(instance.get_cluster_status())
            ch_core.hookenv.action_set({"cluster-status": _status})
        except subprocess.CalledProcessError as e:
            ch_core.hookenv.action_set({
                "time-completed": (strftime("%Y-%m-%d %H:%M:%S", gmtime())),
                "output": e.output,
                "return-code": e.returncode,
                "traceback": traceback.format_exc()})
            ch_core.hookenv.action_fail("Cluster status failed")


# A dictionary of all the defined actions to callables (which take
# parsed arguments).
ACTIONS = {"cluster-status": cluster_status}


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
            ch_core.hookenv.action_fail(str(e))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
