# Copyright 2018 Canonical Ltd
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

import mock

import charm.openstack.mysql_innodb_cluster as mysql_innodb_cluster
import reactive.mysql_innodb_cluster_handlers as handlers

import charms_openstack.test_utils as test_utils


class TestRegisteredHooks(test_utils.TestRegisteredHooks):

    def test_hooks(self):
        defaults = [
            "config.changed",
            "update-status",
            "upgrade-charm",
            "charm.installed"]
        hook_set = {
            "when": {
                "leader_install": (
                    "leadership.is_leader", "snap.installed.mysql-shell",),
                "non_leader_install": ("leadership.set.mysql.passwd",),
                "create_local_cluster_user": ("charm.installed",),
                "send_cluster_connection_info": (
                    "local.cluster.user-created", "cluster.connected",),
                "create_remote_cluster_user": ("cluster.available",),
                "initialize_cluster": (
                    "leadership.is_leader", "local.cluster.user-created",),
                "configure_instances_for_clustering": (
                    "leadership.is_leader", "local.cluster.all-users-created",
                    "leadership.set.cluster-created", "cluster.available"),
                "add_instances_to_cluster": (
                    "leadership.is_leader", "leadership.set.cluster-created",
                    "leadership.set.cluster-instances-configured",
                    "cluster.available",),
                "signal_clustered": (
                    "leadership.set.cluster-created", "cluster.available",),
                "config_changed": (
                    "leadership.set.cluster-instances-clustered",
                    "config.changed",),
                "config_changed_restart": (
                    "coordinator.granted.config-changed-restart",),
                "shared_db_respond": (
                    "leadership.is_leader",
                    "leadership.set.cluster-instances-clustered",
                    "endpoint.shared-db.changed",
                    "shared-db.available",),
                "db_router_respond": (
                    "leadership.is_leader",
                    "leadership.set.cluster-instances-clustered",
                    "endpoint.db-router.changed",
                    "db-router.available",),
                "scale_out": (
                    "endpoint.cluster.changed.unit-configure-ready",
                    "leadership.set.cluster-instances-clustered",
                    "leadership.is_leader",),
                "request_certificates": (
                    "certificates.available",
                    "cluster.available",),
                "configure_certificates": (
                    "certificates.ca.changed",
                    "certificates.certs.changed",),
            },
            "when_not": {
                "leader_install": ("charm.installed",),
                "non_leader_install": (
                    "leadership.is_leader", "charm.installed",),
                "create_local_cluster_user": ("local.cluster.user-created",),
                "send_cluster_connection_info": ("cluster.available",),
                "create_remote_cluster_user": (
                    "local.cluster.all-users-created",),
                "initialize_cluster": ("leadership.set.cluster-created",),
                "configure_instances_for_clustering": (
                    "leadership.set.cluster-instances-configured",),
                "add_instances_to_cluster": (
                    "leadership.set.cluster-instances-clustered",),
                "signal_clustered": ("leadership.is_leader",),
                "shared_db_respond": ("charm.paused",),
                "db_router_respond": ("charm.paused",),
            },
        }
        # test that the hooks were registered via the
        # reactive.mysql_innodb_cluster_handlers
        self.registered_hooks_test_helper(handlers, hook_set, defaults)


class TestMySQLInnoDBClusterHandlers(test_utils.PatchHelper):

    def setUp(self):
        super().setUp()
        self.patch_release(
            mysql_innodb_cluster.MySQLInnoDBClusterCharm.release)
        self.midbc = mock.MagicMock()
        self.midbc.cluster_name = "jujuCluster"
        self.midbc.cluster_address = "10.10.10.10"
        self.midbc.cluster_user = "clusteruser"
        self.midbc.cluster_password = "clusterpass"
        self.patch_object(handlers.charm, "provide_charm_instance",
                          new=mock.MagicMock())
        self.provide_charm_instance().__enter__.return_value = (
            self.midbc)
        self.provide_charm_instance().__exit__.return_value = None
        self.patch_object(handlers.leadership, "leader_set")
        self.patch_object(handlers.reactive, "is_flag_set")
        self.patch_object(handlers.reactive, "set_flag")

        self.unit1 = mock.MagicMock(name="FakeUnit")
        self.unit1.received.__getitem__.side_effect = self._fake_data
        self.cluster = mock.MagicMock()
        self.cluster.all_joined_units = [self.unit1]
        self.shared_db = mock.MagicMock()
        self.shared_db.all_joined_units = [self.unit1]
        self.db_router = mock.MagicMock()
        self.db_router.all_joined_units = [self.unit1]
        self.data = {}
        self.patch_object(handlers.reactive, "endpoint_from_flag",
                          new=mock.MagicMock())

    def _fake_data(self, key):
        return self.data.get(key)

    def test_leader_install(self):
        handlers.leader_install()
        self.midbc.install.assert_called_once()
        self.set_flag.assert_called_once_with("charm.installed")

    def test_non_leader_install(self):
        handlers.non_leader_install()
        self.midbc.install.assert_called_once()
        self.set_flag.assert_called_once_with("charm.installed")

    def test_create_local_cluster_user(self):
        self.midbc.create_cluster_user.return_value = True
        handlers.create_local_cluster_user()
        self.midbc.create_cluster_user.assert_called_once_with(
            self.midbc.cluster_address,
            self.midbc.cluster_user,
            self.midbc.cluster_password)
        self.set_flag.assert_called_once_with("local.cluster.user-created")

        # Not successful
        self.midbc.create_cluster_user.return_value = False
        self.set_flag.reset_mock()
        handlers.create_local_cluster_user()
        self.set_flag.assert_not_called()

    def test_send_cluster_connection_info(self):
        self.endpoint_from_flag.return_value = self.cluster
        handlers.send_cluster_connection_info()
        self.cluster.set_cluster_connection_info.assert_called_once_with(
            self.midbc.cluster_address,
            self.midbc.cluster_user,
            self.midbc.cluster_password)

    def test_create_remote_cluster_user(self):
        _addr = "10.10.10.20"
        _pass = "pass"
        _user = "user"
        self.data = {"cluster-address": _addr,
                     "cluster-user": _user,
                     "cluster-password": _pass}
        self.midbc.create_cluster_user.return_value = True
        self.endpoint_from_flag.return_value = self.cluster
        handlers.create_remote_cluster_user()
        self.midbc.create_cluster_user.assert_called_once_with(
            _addr, _user, _pass)
        self.cluster.set_unit_configure_ready.assert_called_once()
        self.set_flag.assert_called_once_with(
            "local.cluster.all-users-created")

        # Not successful
        self.midbc.create_cluster_user.return_value = False
        self.cluster.set_unit_configure_ready.reset_mock()
        handlers.create_remote_cluster_user()
        self.cluster.set_unit_configure_ready.assert_not_called()

    def test_initialize_cluster(self):
        handlers.initialize_cluster()
        self.midbc.configure_instance.assert_called_once_with(
            self.midbc.cluster_address)
        self.midbc.create_cluster.assert_called_once()

    def test_configure_instances_for_clustering(self):
        _addr = "10.10.10.30"
        self.endpoint_from_flag.return_value = self.cluster
        # Not ready
        self.is_flag_set.return_value = False
        self.data = {"cluster-address": _addr}
        handlers.configure_instances_for_clustering()
        self.midbc.configure_instance.assert_not_called()
        self.midbc.add_instance_to_cluster.assert_not_called()
        self.leader_set.assert_not_called()

        # Some but not all
        self.midbc.reset_mock()
        self.is_flag_set.return_value = False
        self.data = {"cluster-address": _addr, "unit-configure-ready": True}
        handlers.configure_instances_for_clustering()
        self.midbc.configure_instance.assert_called_once_with(_addr)
        self.midbc.add_instance_to_cluster.assert_called_once_with(_addr)
        self.leader_set.assert_not_called()

        # All ready
        self.midbc.reset_mock()
        self.is_flag_set.return_value = True
        handlers.configure_instances_for_clustering()
        self.midbc.configure_instance.assert_called_once_with(_addr)
        self.midbc.add_instance_to_cluster.assert_called_once_with(_addr)
        self.leader_set.assert_called_once_with(
            {"cluster-instances-configured": True})

    def test_add_instances_to_cluster(self):
        _addr = "10.10.10.30"
        self.endpoint_from_flag.return_value = self.cluster

        # Some but not all
        self.is_flag_set.return_value = False
        self.data = {"cluster-address": _addr}
        handlers.add_instances_to_cluster()
        self.midbc.add_instance_to_cluster.assert_called_once_with(_addr)
        self.leader_set.assert_not_called()

        # All ready
        self.midbc.reset_mock()
        self.is_flag_set.return_value = True
        handlers.add_instances_to_cluster()
        self.midbc.add_instance_to_cluster.assert_called_once_with(_addr)
        self.leader_set.assert_called_once_with(
            {"cluster-instances-clustered": True})

    def test_signal_clustered(self):
        # Unit not clustered
        self.endpoint_from_flag.return_value = self.cluster
        self.is_flag_set.return_value = False
        handlers.signal_clustered()
        self.cluster.set_unit_clustered.assert_not_called()

        # Unit Clustered
        self.midbc.reset_mock()
        self.is_flag_set.return_value = True
        handlers.signal_clustered()
        self.cluster.set_unit_clustered.assert_called_once()

    def test_config_changed(self):
        # Leader node
        self.is_flag_set.return_value = True
        handlers.config_changed()
        self.midbc.render_all_configs.assert_called_once()
        self.midbc.wait_until_cluster_available.assert_called_once()

    def test_shared_db_respond(self):
        self.endpoint_from_flag.return_value = self.shared_db
        handlers.shared_db_respond()
        self.midbc.create_databases_and_users.assert_called_once_with(
            self.shared_db)

    def test_db_router_respond(self):
        self.endpoint_from_flag.return_value = self.db_router
        handlers.db_router_respond()
        self.midbc.create_databases_and_users.assert_called_once_with(
            self.db_router)
