# Copyright 2022 Canonical Ltd
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

from unittest import mock

import charm.openstack.mysql_innodb_cluster as mysql_innodb_cluster
import reactive.prometheus_mysql_exporter_handlers as handlers

import charms_openstack.test_utils as test_utils


class TestRegisteredHooks(test_utils.TestRegisteredHooks):

    def test_hooks(self):
        defaults = [
        ]
        hook_set = {
            "when": {
                "create_local_prometheus_exporter_user": (
                    "prometheus.available",
                    "local.cluster.user-created",
                ),
                "snap_install_prometheus_exporter": (
                    "prometheus.available",
                ),
                "start_prometheus_exporter_service": (
                    "prometheus.available",
                    "snap.installed.prometheus-exporter",
                    "local.prom-exporter.user-created",
                    "local.prom-exporter.all-user-created",
                ),
                "send_prometheus_connection_info": (
                    "snap.prometheus-exporter.started",
                    "prometheus.available",
                ),
                "stop_prometheus_exporter_service": (
                    "snap.prometheus-exporter.started",
                ),
                "prometheus_connected": (
                    "prometheus.available",
                ),
                "maybe_update_snap_channel": (
                    "snap.prometheus_exporter.check-config-changed",
                ),
                "prometheus_disconnected": (
                    "local.prometheus.send-connection-info",
                ),
                "set_config_changed_snap_check": (
                    "prometheus.available",
                    "config.changed",
                ),
                "create_remote_prometheus_exporter_user": (
                    "prometheus.available",
                    "cluster.available",
                    "local.prom-exporter.user-created",
                ),
            },
            "when_not": {
                "create_local_prometheus_exporter_user": (
                    "local.prom-exporter.user-created",
                ),
                "snap_install_prometheus_exporter": (
                    "snap.installed.prometheus-exporter",
                ),
                "start_prometheus_exporter_service": (
                    "snap.prometheus-exporter.started",
                ),
                "stop_prometheus_exporter_service": (
                    "prometheus.available",
                ),
                "prometheus_disconnected": (
                    "prometheus.available",
                ),
                "send_prometheus_connection_info": (
                    "local.prometheus.send-connection-info",
                ),

                "prometheus_connected": (
                    "local.prometheus.send-connection-info",
                ),
                "create_remote_prometheus_exporter_user": (
                    "local.prom-exporter.all-user-created",
                ),
            },
        }
        self.registered_hooks_test_helper(handlers, hook_set, defaults)


class TestPrometheusMySQLExporterHandlers(test_utils.PatchHelper):

    def setUp(self):
        super().setUp()

        self._snap_name = "mysqld-exporter"
        self._svc_name = (
            "snap.mysqld-exporter.mysqld-exporter.service"
        )

        # Patch
        self.patch_release(
            mysql_innodb_cluster.MySQLInnoDBClusterCharm.release)
        self.midbc = mock.MagicMock()

        self.midbc.prometheus_exporter_user = "prom_exporter"
        self.midbc.prometheus_exporter_password = "clusterpass"
        self.midbc.cluster_address = "10.10.10.10"
        self.midbc.cluster_port = 1234

        self.patch_object(handlers.charm, "provide_charm_instance",
                          new=mock.MagicMock())
        self.provide_charm_instance().__enter__.return_value = (
            self.midbc)
        self.provide_charm_instance().__exit__.return_value = None
        self.patch_object(
            handlers.reactive, "is_flag_set")
        self.patch_object(handlers.reactive, "set_flag")
        self.patch_object(handlers.reactive, "remove_state")
        self.patch_object(
            obj=handlers.snap, attr="install", name="snap_install")
        self.patch_object(obj=handlers.snap, attr="set", name="snap_set")

        self.patch_object(
            handlers.ch_core.hookenv, "status_set")

        self.patch_object(
            handlers.ch_core.host, "service_restart")

        self.patch_object(
            handlers.ch_core.host, "service_stop")

        self.patch_object(
            handlers.ch_core.hookenv, "config"
        )
        self.config.return_value = {}

    def test_create_local_prometheus_expoter_user(self):
        self.midbc.create_user.return_value = True
        self.midbc.prometheus_exporter_password = 'mypassword'
        handlers.create_local_prometheus_exporter_user()
        self.midbc.create_user.assert_called_once_with(
            self.midbc.cluster_address,
            self.midbc.prometheus_exporter_user,
            self.midbc.prometheus_exporter_password,
            "prom_exporter",
        )
        self.set_flag.assert_called_once_with(
            "local.prom-exporter.user-created")

    def test_create_local_prometheus_expoter_user_non_set_password(self):
        self.midbc.create_user.return_value = True
        self.midbc.prometheus_exporter_password = None
        handlers.create_local_prometheus_exporter_user()
        self.midbc.create_user.assert_not_called()

    def test_snap_install_prometheus_exporter(self):

        handlers.snap_install_prometheus_exporter()
        self.snap_install.assert_called_once_with(
            self._snap_name,
            channel="stable",
            force_dangerous=False,
        )
        self.set_flag.assert_called_once_with(
            "snap.installed.prometheus-exporter")
        self.status_set.assert_has_calls(
            [
                mock.call(
                    "maintenance",
                    "Snap install {}. channel=stable".format(self._snap_name),
                ),
                mock.call(
                    "active",
                    "Snap install {} success. channel=stable".format(
                        self._snap_name),
                )
            ]
        )

    def test_snap_config_prometheus_exporter(self):
        handlers.snap_config_prometheus_exporter(self.midbc)
        self.snap_set.assert_any_call(
            self._snap_name, "mysql.port", self.midbc.cluster_port
        )
        self.snap_set.assert_any_call(
            self._snap_name, "mysql.host", self.midbc.cluster_address
        )
        self.snap_set.assert_any_call(
            self._snap_name, "mysql.user", self.midbc.prometheus_exporter_user,
        )
        self.snap_set.assert_any_call(
            self._snap_name,
            "mysql.password",
            self.midbc.prometheus_exporter_password,
        )
        self.set_flag.assert_called_once_with(
            "snap.prometheus-exporter.configed")

    def test_prometheus_connected(self):
        handlers.prometheus_connected()
        self.status_set.assert_called_once_with(
            "maintenance", "Start prometheus exporter service")

    def test_prometheus_disconnected(self):
        handlers.prometheus_disconnected()
        self.status_set.assert_called_once_with(
            "maintenance", "Stop prometheus exporter service")

    def test_start_prometheus_exporter(self):
        handlers.start_prometheus_exporter()
        self.service_restart.assert_called_once_with(self._svc_name)
        self.set_flag("snap.prometheus-exporter.started")

    @mock.patch.object(handlers, "start_prometheus_exporter")
    @mock.patch.object(handlers, "snap_config_prometheus_exporter")
    def test_start_prometheus_exporter_service(
        self,
        snap_config_prometheus_exporter,
        start_prometheus_exporter,
    ):
        # Already configed
        self.is_flag_set.return_value = True
        handlers.start_prometheus_exporter_service()
        snap_config_prometheus_exporter.assert_not_called()
        start_prometheus_exporter.assert_called_once_with()

        snap_config_prometheus_exporter.reset_mock()
        start_prometheus_exporter.reset_mock()

        # Not configed
        self.is_flag_set.return_value = False
        handlers.start_prometheus_exporter_service()
        snap_config_prometheus_exporter.assert_called_once_with(
            self.midbc,
        )
        start_prometheus_exporter.assert_called_once_with()

    def test_send_prometheus_connection_info(self):
        target = mock.MagicMock()
        handlers.send_prometheus_connection_info(target)
        target.configure.assert_called_once_with(
            port=self.midbc.prometheus_exporter_port,
        )
        self.status_set.assert_called_once_with(
            "active", "Start prometheus exporter service")
        self.set_flag.assert_called_once_with(
            "local.prometheus.send-connection-info"
        )

    def test_stop_prometheus_exporter_service(self):
        handlers.stop_prometheus_exporter_service()
        self.service_stop.assert_called_once_with(self._svc_name)
        expected_calls = [
            mock.call("snap.prometheus-exporter.configed"),
            mock.call("snap.prometheus-exporter.started")
        ]
        self.remove_state.assert_has_calls(expected_calls)
        self.status_set.assert_called_once_with(
            "active", "Stop prometheus exporter service")
