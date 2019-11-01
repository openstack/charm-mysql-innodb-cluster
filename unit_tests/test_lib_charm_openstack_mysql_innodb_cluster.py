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

import copy
import collections
import mock

import charms_openstack.test_utils as test_utils

import charm.openstack.mysql_innodb_cluster as mysql_innodb_cluster


class TestMySQLInnoDBClusterProperties(test_utils.PatchHelper):

    def setUp(self):
        super().setUp()
        self.cls = mock.MagicMock()
        self.patch_object(mysql_innodb_cluster.ch_core.hookenv, "local_unit")
        self.patch_object(mysql_innodb_cluster.ch_net_ip, "get_relation_ip")

    def test_server_id(self):
        self.local_unit.return_value = "unit/5"
        self.assertEqual(mysql_innodb_cluster.server_id(self.cls), "1005")

    def test_cluster_address(self):
        _addr = "10.10.10.10"
        self.get_relation_ip.return_value = _addr
        self.assertEqual(mysql_innodb_cluster.cluster_address(self.cls), _addr)
        self.get_relation_ip.assert_called_once_with("cluster")

    def test_shared_db_address(self):
        _addr = "10.10.10.20"
        self.get_relation_ip.return_value = _addr
        self.assertEqual(
            mysql_innodb_cluster.shared_db_address(self.cls), _addr)
        self.get_relation_ip.assert_called_once_with("shared-db")

    def test_db_router_address(self):
        _addr = "10.10.10.30"
        self.get_relation_ip.return_value = _addr
        self.assertEqual(
            mysql_innodb_cluster.db_router_address(self.cls), _addr)
        self.get_relation_ip.assert_called_once_with("db-router")


class TestMySQLInnoDBClusterCharm(test_utils.PatchHelper):

    def setUp(self):
        super().setUp()
        self.patch_object(mysql_innodb_cluster, "subprocess")
        self.patch_object(mysql_innodb_cluster.uuid, "uuid4")
        self.uuid_of_cluster = "uuid-of-cluster"
        self.uuid4.return_value = self.uuid_of_cluster
        self.patch_object(mysql_innodb_cluster.reactive, "is_flag_set")
        self.patch_object(mysql_innodb_cluster.reactive, "set_flag")
        self.patch_object(mysql_innodb_cluster.ch_net_ip, "get_relation_ip")
        self.patch_object(mysql_innodb_cluster.ch_core.host, "pwgen")
        self.patch_object(mysql_innodb_cluster.ch_core.hookenv, "is_leader")
        self.patch_object(mysql_innodb_cluster.leadership, "leader_set")
        self.patch_object(mysql_innodb_cluster.ch_core.hookenv, "leader_get")
        self.patch_object(mysql_innodb_cluster.ch_core.hookenv, "config")
        self.patch_object(
            mysql_innodb_cluster.ch_core.hookenv, "application_version_set")
        self.leader_get.side_effect = self._fake_leader_data
        self.config.side_effect = self._fake_config_data
        self.leader_data = {}
        self.config_data = {}
        self.data = {}
        self.stdin = mock.MagicMock()
        self.filename = "script.js"
        self.file = mock.MagicMock()
        self.file.name = self.filename
        self.ntf = mock.MagicMock()
        self.ntf.__enter__.return_value = self.file
        self.ntf.__enter__.name.return_value = self.filename
        self.wait_until = mock.MagicMock()
        self.patch_object(mysql_innodb_cluster.tempfile, "NamedTemporaryFile")
        self.NamedTemporaryFile.return_value = self.ntf
        self.subprocess.STDOUT = self.stdin

        # Complex setup for create_databases_and_users tests
        # mimics a reactive env
        self.mock_unprefixed = "UNPREFIXED"
        self.keystone_shared_db = mock.MagicMock()
        self.keystone_shared_db.relation_id = "shared-db:5"
        self.nova_shared_db = mock.MagicMock()
        self.nova_shared_db.relation_id = "shared-db:20"
        self.kmr_db_router = mock.MagicMock()
        self.kmr_db_router.relation_id = "db-router:7"
        self.nmr_db_router = mock.MagicMock()
        self.nmr_db_router.relation_id = "db-router:10"
        # Keystone shared-db
        self.keystone_unit5_name = "keystone/5"
        self.keystone_unit5_ip = "10.10.10.50"
        self.keystone_unit5 = mock.MagicMock()
        self.keystone_unit5.received = {
            "database": "keystone", "username": "keystone",
            "hostname": self.keystone_unit5_ip}
        self.keystone_unit5.unit_name = self.keystone_unit5_name
        self.keystone_unit5.relation = self.keystone_shared_db
        self.keystone_unit7_name = "keystone/7"
        self.keystone_unit7_ip = "10.10.10.70"
        self.keystone_unit7 = mock.MagicMock()
        self.keystone_unit7.received = {
            "database": "keystone", "username": "keystone",
            "hostname": self.keystone_unit7_ip}
        self.keystone_unit7.unit_name = self.keystone_unit7_name
        self.keystone_unit7.relation = self.keystone_shared_db
        self.keystone_shared_db.joined_units = [
            self.keystone_unit5, self.keystone_unit7]
        # Nova shared-db
        self.nova_unit5_name = "nova/5"
        self.nova_unit5_ip = "10.20.20.50"
        self.nova_unit5 = mock.MagicMock()
        self.nova_unit5.unit_name = self.nova_unit5_name
        self.nova_unit5.relation = self.nova_shared_db
        self.nova_unit5.received = {
            "nova_database": "nova", "nova_username": "nova",
            "nova_hostname": self.nova_unit5_ip,
            "novaapi_database": "nova_api", "novaapi_username": "nova",
            "novaapi_hostname": self.nova_unit5_ip,
            "novacell0_database": "nova_cell0", "novacell0_username": "nova",
            "novacell0_hostname": self.nova_unit5_ip}
        self.nova_unit7_name = "nova/7"
        self.nova_unit7_ip = "10.20.20.70"
        self.nova_unit7 = mock.MagicMock()
        self.nova_unit7.unit_name = self.nova_unit7_name
        self.nova_unit7.received = {
            "nova_database": "nova", "nova_username": "nova",
            "nova_hostname": self.nova_unit7_ip,
            "novaapi_database": "nova_api", "novaapi_username": "nova",
            "novaapi_hostname": self.nova_unit7_ip,
            "novacell0_database": "nova_cell0", "novacell0_username": "nova",
            "novacell0_hostname": self.nova_unit7_ip}
        self.nova_unit7.relation = self.nova_shared_db
        self.nova_shared_db.joined_units = [self.nova_unit5, self.nova_unit7]
        # Keystone db-router
        self.kmr_unit5_name = "kmr/5"
        self.kmr_unit5_ip = "10.30.30.50"
        self.kmr_unit5 = mock.MagicMock()
        self.kmr_unit5.unit_name = self.kmr_unit5_name
        self.kmr_unit5.relation = self.kmr_db_router
        self.kmr_unit5.received = {
            "{}_database".format(self.mock_unprefixed): "keystone",
            "{}_username".format(self.mock_unprefixed): "keystone",
            "{}_hostname".format(self.mock_unprefixed): self.kmr_unit5_ip,
            "mysqlrouter_username": "mysqlrouteruser",
            "mysqlrouter_hostname": self.kmr_unit5_ip}
        self.kmr_unit7_name = "kmr/7"
        self.kmr_unit7_ip = "10.30.30.70"
        self.kmr_unit7 = mock.MagicMock()
        self.kmr_unit7.unit_name = self.kmr_unit7_name
        self.kmr_unit7.relation = self.kmr_db_router
        self.kmr_db_router.joined_units = [self.kmr_unit5, self.kmr_unit7]
        self.kmr_unit7.received = {
            "{}_database".format(self.mock_unprefixed): "keystone",
            "{}_username".format(self.mock_unprefixed): "keystone",
            "{}_hostname".format(self.mock_unprefixed): self.kmr_unit7_ip,
            "mysqlrouter_username": "mysqlrouteruser",
            "mysqlrouter_hostname": self.kmr_unit7_ip}
        # Nova Router db-router
        self.nmr_unit5_name = "nmr/5"
        self.nmr_unit5_ip = "10.40.40.50"
        self.nmr_unit5 = mock.MagicMock()
        self.nmr_unit5.unit_name = self.nmr_unit5_name
        self.nmr_unit5.relation = self.nmr_db_router
        self.nmr_unit5.received = {
            "nova_database": "nova", "nova_username": "nova",
            "nova_hostname": self.nmr_unit5_ip,
            "novaapi_database": "nova_api", "novaapi_username": "nova",
            "novaapi_hostname": self.nmr_unit5_ip,
            "novacell0_database": "nova_cell0",
            "novacell0_username": "nova",
            "novacell0_hostname": self.nmr_unit5_ip,
            "mysqlrouter_username": "mysqlrouteruser",
            "mysqlrouter_hostname": self.nmr_unit5_ip}
        self.nmr_unit7_name = "nmr/7"
        self.nmr_unit7_ip = "10.40.40.70"
        self.nmr_unit7 = mock.MagicMock()
        self.nmr_unit7.unit_name = self.nmr_unit7_name
        self.nmr_unit7.relation = self.nmr_db_router
        self.nmr_db_router.joined_units = [self.nmr_unit5, self.nmr_unit7]
        self.nmr_unit7.received = {
            "nova_database": "nova", "nova_username": "nova",
            "nova_hostname": self.nmr_unit7_ip,
            "novaapi_database": "nova_api", "novaapi_username": "nova",
            "novaapi_hostname": self.nmr_unit7_ip,
            "novacell0_database": "nova_cell0",
            "novacell0_username": "nova",
            "novacell0_hostname": self.nmr_unit7_ip,
            "mysqlrouter_username": "mysqlrouteruser",
            "mysqlrouter_hostname": self.nmr_unit7_ip}

        # Generic interface
        self.interface = mock.MagicMock()

    def _fake_leader_data(self, key):
        return self.leader_data.get(key)

    def _fake_config_data(self, key=None):
        if key is None:
            return {}
        return self.config_data.get(key)

    def _fake_data(self, key):
        return self.data.get(key)

    def _fake_configure(self, *args, **kwargs):
        # For use mocking configure_db_router and configure_db_for_hosts
        # Return the same password for the same username
        if len(args) == 3:
            # configure_db_for_hosts
            return "{}-pwd".format(args[2])
        elif len(args) == 2:
            # configure_db_router
            return "{}-pwd".format(args[1])

    def _fake_get_allowed_units(self, *args, **kwargs):
        return " ".join(
            [x.unit_name for x in
                self.interface.relations[args[2]].joined_units])

    def _fake_get_db_data(self, relation_data, unprefixed=None):
        # This "fake" get_db_data looks a lot like the real thing.
        # Charmhelpers is mocked out entirely and attempting to
        # mock the output made the test setup more difficult.
        settings = copy.deepcopy(relation_data)
        databases = collections.OrderedDict()

        singleset = {"database", "username", "hostname"}
        if singleset.issubset(settings):
            settings["{}_{}".format(unprefixed, "hostname")] = (
                settings["hostname"])
            settings.pop("hostname")
            settings["{}_{}".format(unprefixed, "database")] = (
                settings["database"])
            settings.pop("database")
            settings["{}_{}".format(unprefixed, "username")] = (
                settings["username"])
            settings.pop("username")

        for k, v in settings.items():
            db = k.split("_")[0]
            x = "_".join(k.split("_")[1:])
            if db not in databases:
                databases[db] = collections.OrderedDict()
            databases[db][x] = v

        return databases

    def test_mysqlsh_bin(self):
        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        self.assertEqual(
            midbc.mysqlsh_bin,
            "/snap/mysql-shell/current/usr/bin/mysqlsh")

    def test_mysql_password(self):
        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        midbc._get_password = mock.MagicMock()
        midbc._get_password.side_effect = self._fake_data
        _pass = "pass123"
        self.data = {"mysql.passwd": _pass}
        self.assertEqual(
            midbc.mysql_password,
            _pass)

    def test_cluster_name(self):
        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        _name = "jujuCluster"
        midbc.options.cluster_name = _name
        self.assertEqual(
            midbc.cluster_name,
            _name)

    def test_cluster_password(self):
        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        midbc._get_password = mock.MagicMock()
        midbc._get_password.side_effect = self._fake_data
        _pass = "pass321"
        self.data = {"cluster-password": _pass}
        self.assertEqual(
            midbc.cluster_password,
            _pass)

    def test_cluster_address(self):
        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        _addr = "10.10.10.50"
        self.get_relation_ip.return_value = _addr
        self.assertEqual(
            midbc.cluster_address,
            _addr)

    def test_cluster_user(self):
        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        self.assertEqual(
            midbc.cluster_user,
            "clusteruser")

    def test_shared_db_address(self):
        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        _addr = "10.10.10.60"
        self.get_relation_ip.return_value = _addr
        self.assertEqual(
            midbc.shared_db_address,
            _addr)

    def test_db_router_address(self):
        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        _addr = "10.10.10.70"
        self.get_relation_ip.return_value = _addr
        self.assertEqual(
            midbc.db_router_address,
            _addr)

    def test__get_password(self):
        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        # Pwgen
        _pwgenpass = "pwgenpass"
        self.pwgen.return_value = _pwgenpass
        self.assertEqual(
            midbc._get_password("pwgenpw"),
            _pwgenpass)
        # Config
        _configpass = "configpass"
        self.config_data = {"configpw": _configpass}
        self.assertEqual(
            midbc._get_password("configpw"),
            _configpass)
        # Leader settings
        _leaderpass = "leaderpass"
        self.leader_data = {"leaderpw": _leaderpass}
        self.assertEqual(
            midbc._get_password("leaderpw"),
            _leaderpass)

    def test_configure_mysql_password(self):
        _pass = "mysql-pass"
        self.data = {"mysql.passwd": _pass}
        _debconf = mock.MagicMock()
        self.subprocess.Popen.return_value = _debconf
        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        midbc._get_password = mock.MagicMock()
        midbc._get_password.side_effect = self._fake_data
        midbc.configure_mysql_password()
        _calls = []
        for package in ["mysql-server", "mysql-server-8.0"]:
            _calls.append(
                mock.call("{} {}/root_password password {}\n"
                          .format(package, package, _pass).encode("UTF-8")))
            _calls.append(
                mock.call("{} {}/root_password_again password {}\n"
                          .format(package, package, _pass).encode("UTF-8")))
        _debconf.stdin.write.assert_has_calls(_calls, any_order=True)

    def test_install(self):
        self.patch_object(
            mysql_innodb_cluster.charms_openstack.charm.OpenStackCharm,
            "install", "super_install")
        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        midbc.configure_mysql_password = mock.MagicMock()
        midbc.configure_source = mock.MagicMock()
        midbc.render_all_configs = mock.MagicMock()
        midbc.install()
        self.super_install.assert_called_once()
        midbc.configure_mysql_password.assert_called_once()
        midbc.configure_source.assert_called_once()
        midbc.render_all_configs.assert_called_once()

    def test_get_db_helper(self):
        _helper = mock.MagicMock()
        self.patch_object(
            mysql_innodb_cluster.mysql, "MySQL8Helper")
        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        self.MySQL8Helper.return_value = _helper
        self.assertEqual(_helper, midbc.get_db_helper())
        self.MySQL8Helper.assert_called_once()

    def test_create_cluster_user(self):
        _user = "user"
        _pass = "pass"
        _addr = "10.10.20.20"
        _helper = mock.MagicMock()
        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        midbc.get_db_helper = mock.MagicMock()
        midbc.get_db_helper.return_value = _helper
        # Non-local
        midbc.create_cluster_user(_addr, _user, _pass)
        _calls = [
            mock.call("CREATE USER '{}'@'{}' IDENTIFIED BY '{}'"
                      .format(_user, _addr, _pass)),
            mock.call("GRANT ALL PRIVILEGES ON *.* TO '{}'@'{}'"
                      .format(_user, _addr)),
            mock.call("GRANT GRANT OPTION ON *.* TO '{}'@'{}'"
                      .format(_user, _addr)),
            mock.call("flush privileges")]
        _helper.execute.assert_has_calls(
            _calls, any_order=True)

        # Local
        _localhost = "localhost"
        _helper.reset_mock()
        self.get_relation_ip.return_value = _addr
        midbc.create_cluster_user(_addr, _user, _pass)
        _calls = [
            mock.call("CREATE USER '{}'@'{}' IDENTIFIED BY '{}'"
                      .format(_user, _addr, _pass)),
            mock.call("GRANT ALL PRIVILEGES ON *.* TO '{}'@'{}'"
                      .format(_user, _addr)),
            mock.call("GRANT GRANT OPTION ON *.* TO '{}'@'{}'"
                      .format(_user, _addr)),
            mock.call('flush privileges'),
            mock.call("CREATE USER '{}'@'{}' IDENTIFIED BY '{}'"
                      .format(_user, _localhost, _pass)),
            mock.call("GRANT ALL PRIVILEGES ON *.* TO '{}'@'{}'"
                      .format(_user, _localhost)),
            mock.call("GRANT GRANT OPTION ON *.* TO '{}'@'{}'"
                      .format(_user, _localhost)),
            mock.call("flush privileges")]
        _helper.execute.assert_has_calls(
            _calls, any_order=True)

    def test_configure_instance(self):
        _pass = "clusterpass"
        _addr = "10.10.30.30"
        self.data = {"cluster-password": _pass}
        self.is_flag_set.return_value = False

        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        midbc._get_password = mock.MagicMock()
        midbc._get_password.side_effect = self._fake_data
        midbc.wait_until_connectable = mock.MagicMock()
        midbc.run_mysqlsh_script = mock.MagicMock()
        _script = """
        dba.configureInstance('{}:{}@{}');
        var myshell = shell.connect('{}:{}@{}');
        myshell.runSql("RESTART;");
        """.format(
            midbc.cluster_user, midbc.cluster_password, _addr,
            midbc.cluster_user, midbc.cluster_password, _addr)

        midbc.configure_instance(_addr)
        self.is_flag_set.assert_called_once_with(
            "leadership.set.cluster-instance-configured-{}".format(_addr))
        midbc.run_mysqlsh_script.assert_called_once_with(_script)
        midbc.wait_until_connectable.assert_called_once_with(
            address=_addr, username=midbc.cluster_user,
            password=midbc.cluster_password)
        self.leader_set.assert_called_once_with(
            {"cluster-instance-configured-{}".format(_addr): True})

    def test_create_cluster(self):
        _pass = "clusterpass"
        _addr = "10.10.40.40"
        _name = "jujuCluster"
        self.get_relation_ip.return_value = _addr
        self.data = {"cluster-password": _pass}
        self.is_flag_set.side_effect = [False, True]

        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        midbc._get_password = mock.MagicMock()
        midbc._get_password.side_effect = self._fake_data
        midbc.wait_until_connectable = mock.MagicMock()
        midbc.run_mysqlsh_script = mock.MagicMock()
        midbc.options.cluster_name = _name
        _script = """
        shell.connect("{}:{}@{}")
        var cluster = dba.createCluster("{}");
        """.format(
            midbc.cluster_user, midbc.cluster_password,
            midbc.cluster_address, midbc.cluster_name)

        midbc.create_cluster()
        _is_flag_set_calls = [
            mock.call("leadership.set.cluster-created"),
            mock.call("leadership.set.cluster-instance-configured-{}"
                      .format(_addr))]
        self.is_flag_set.assert_has_calls(_is_flag_set_calls, any_order=True)
        midbc.run_mysqlsh_script.assert_called_once_with(_script)
        _leader_set_calls = [
            mock.call({"cluster-instance-clustered-{}".format(_addr): True}),
            mock.call({"cluster-created": self.uuid_of_cluster})]
        self.leader_set.assert_has_calls(_leader_set_calls, any_order=True)

    def test_add_instance_to_cluster(self):
        _pass = "clusterpass"
        _local_addr = "10.10.50.50"
        _remote_addr = "10.10.60.60"
        _name = "theCluster"
        self.get_relation_ip.return_value = _local_addr
        self.data = {"cluster-password": _pass}
        self.is_flag_set.return_value = False

        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        midbc._get_password = mock.MagicMock()
        midbc._get_password.side_effect = self._fake_data
        midbc.wait_until_connectable = mock.MagicMock()
        midbc.run_mysqlsh_script = mock.MagicMock()
        midbc.options.cluster_name = _name
        _script = """
        shell.connect("{}:{}@{}")
        var cluster = dba.getCluster("{}");

        print("Adding instances to the cluster.");
        cluster.addInstance(
            {{user: "{}", host: "{}", password: "{}", port: "3306"}},
            {{recoveryMethod: "clone"}});
        """.format(
            midbc.cluster_user, midbc.cluster_password,
            midbc.cluster_address, midbc.cluster_name,
            midbc.cluster_user, _remote_addr, midbc.cluster_password)

        midbc.add_instance_to_cluster(_remote_addr)
        self.is_flag_set.assert_called_once_with(
            "leadership.set.cluster-instance-clustered-{}"
            .format(_remote_addr))
        midbc.run_mysqlsh_script.assert_called_once_with(_script)
        self.leader_set.assert_called_once_with(
            {"cluster-instance-clustered-{}".format(_remote_addr): True})

    def test_get_allowed_units(self):
        _allowed = ["unit/2", "unit/1", "unit/0"]
        _expected = "unit/0 unit/1 unit/2"
        _helper = mock.MagicMock()
        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        midbc.get_db_helper = mock.MagicMock()
        midbc.get_db_helper.return_value = _helper
        _helper.get_allowed_units.return_value = _allowed
        self.assertEqual(
            _expected,
            midbc.get_allowed_units("db", "user", "rel:2"))

    def test_create_databases_and_users_shared_db(self):
        # The test setup is a bit convoluted and requires mimicking reactive,
        # however, this is the heart of the charm and therefore deserves to
        # be thoroughly tested. It is important to have multiple relations and
        # multiple units per relation.
        self.patch_object(
            mysql_innodb_cluster.mysql, "get_db_data")
        self.get_db_data.side_effect = self._fake_get_db_data

        _addr = "10.99.99.99"
        self.get_relation_ip.return_value = _addr

        self.interface.relations = {
            self.keystone_shared_db.relation_id: self.keystone_shared_db,
            self.nova_shared_db.relation_id: self.nova_shared_db}

        self.interface.all_joined_units = []
        for rel in self.interface.relations.values():
            self.interface.all_joined_units.extend(rel.joined_units)

        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        midbc.get_allowed_units = mock.MagicMock()
        midbc.get_allowed_units.side_effect = self._fake_get_allowed_units

        midbc.configure_db_for_hosts = mock.MagicMock()
        midbc.configure_db_for_hosts.side_effect = self._fake_configure
        midbc.configure_db_router = mock.MagicMock()

        # Execute the function under test
        midbc.create_databases_and_users(self.interface)

        # Validate
        midbc.configure_db_router.assert_not_called()

        _configure_db_calls = [
            mock.call(self.keystone_unit5_ip, "keystone", "keystone"),
            mock.call(self.keystone_unit7_ip, "keystone", "keystone"),
            mock.call(self.nova_unit5_ip, "nova", "nova"),
            mock.call(self.nova_unit5_ip, "nova_api", "nova"),
            mock.call(self.nova_unit5_ip, "nova_cell0", "nova"),
            mock.call(self.nova_unit7_ip, "nova", "nova"),
            mock.call(self.nova_unit7_ip, "nova_api", "nova"),
            mock.call(self.nova_unit7_ip, "nova_cell0", "nova")]
        midbc.configure_db_for_hosts.assert_has_calls(
            _configure_db_calls, any_order=True)

        _set_calls = [
            mock.call(
                self.keystone_shared_db.relation_id, _addr, "keystone-pwd",
                allowed_units=self._fake_get_allowed_units(
                    None, None, self.keystone_shared_db.relation_id),
                prefix=None),
            mock.call(
                self.nova_shared_db.relation_id, _addr, "nova-pwd",
                allowed_units=self._fake_get_allowed_units(
                    None, None, self.nova_shared_db.relation_id),
                prefix="nova"),
            mock.call(
                self.nova_shared_db.relation_id, _addr, "nova-pwd",
                allowed_units=self._fake_get_allowed_units(
                    None, None, self.nova_shared_db.relation_id),
                prefix="novaapi"),
            mock.call(
                self.nova_shared_db.relation_id, _addr, "nova-pwd",
                allowed_units=self._fake_get_allowed_units(
                    None, None, self.nova_shared_db.relation_id),
                prefix="novacell0")]
        self.interface.set_db_connection_info.assert_has_calls(
            _set_calls, any_order=True)

    def test_create_databases_and_users_db_router(self):
        # The test setup is a bit convoluted and requires mimicking reactive,
        # however, this is the heart of the charm and therefore deserves to
        # be thoroughly tested. It is important to have multiple relations and
        # multiple units per relation.
        self.patch_object(
            mysql_innodb_cluster.mysql, "get_db_data")
        self.get_db_data.side_effect = self._fake_get_db_data

        _addr = "10.99.99.99"
        self.get_relation_ip.return_value = _addr

        self.interface.relations = {
            self.kmr_db_router.relation_id: self.kmr_db_router,
            self.nmr_db_router.relation_id: self.nmr_db_router}

        self.interface.all_joined_units = []
        for rel in self.interface.relations.values():
            self.interface.all_joined_units.extend(rel.joined_units)

        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        midbc.get_allowed_units = mock.MagicMock()
        midbc.get_allowed_units.side_effect = self._fake_get_allowed_units
        midbc.configure_db_for_hosts = mock.MagicMock()
        midbc.configure_db_for_hosts.side_effect = self._fake_configure
        midbc.configure_db_router = mock.MagicMock()
        midbc.configure_db_router.side_effect = self._fake_configure

        # Execute the function under test
        midbc.create_databases_and_users(self.interface)

        # Validate
        _conigure_db_router_calls = [
            mock.call(self.kmr_unit5_ip, "mysqlrouteruser"),
            mock.call(self.kmr_unit7_ip, "mysqlrouteruser"),
            mock.call(self.nmr_unit5_ip, "mysqlrouteruser"),
            mock.call(self.nmr_unit7_ip, "mysqlrouteruser")]
        midbc.configure_db_router.assert_has_calls(
            _conigure_db_router_calls, any_order=True)

        _configure_db_calls = [
            mock.call(self.kmr_unit5_ip, "keystone", "keystone"),
            mock.call(self.kmr_unit7_ip, "keystone", "keystone"),
            mock.call(self.nmr_unit5_ip, "nova", "nova"),
            mock.call(self.nmr_unit5_ip, "nova_api", "nova"),
            mock.call(self.nmr_unit5_ip, "nova_cell0", "nova"),
            mock.call(self.nmr_unit7_ip, "nova", "nova"),
            mock.call(self.nmr_unit7_ip, "nova_api", "nova"),
            mock.call(self.nmr_unit7_ip, "nova_cell0", "nova")]
        midbc.configure_db_for_hosts.assert_has_calls(
            _configure_db_calls, any_order=True)

        _set_calls = [
            mock.call(
                self.kmr_db_router.relation_id, _addr, "keystone-pwd",
                allowed_units=self._fake_get_allowed_units(
                    None, None, self.kmr_db_router.relation_id),
                prefix=self.mock_unprefixed),
            mock.call(
                self.kmr_db_router.relation_id, _addr, "mysqlrouteruser-pwd",
                allowed_units=" ".join(
                    [x.unit_name for x in self.kmr_db_router.joined_units]),
                prefix="mysqlrouter"),

            mock.call(
                self.nmr_db_router.relation_id, _addr, "nova-pwd",
                allowed_units=self._fake_get_allowed_units(
                    None, None, self.nmr_db_router.relation_id),
                prefix="nova"),
            mock.call(
                self.nmr_db_router.relation_id, _addr, "nova-pwd",
                allowed_units=self._fake_get_allowed_units(
                    None, None, self.nmr_db_router.relation_id),
                prefix="novaapi"),
            mock.call(
                self.nmr_db_router.relation_id, _addr, "nova-pwd",
                allowed_units=self._fake_get_allowed_units(
                    None, None, self.nmr_db_router.relation_id),
                prefix="novacell0"),
            mock.call(
                self.nmr_db_router.relation_id, _addr, "mysqlrouteruser-pwd",
                allowed_units=" ".join(
                    [x.unit_name for x in self.nmr_db_router.joined_units]),
                prefix="mysqlrouter")]
        self.interface.set_db_connection_info.assert_has_calls(
            _set_calls, any_order=True)

    def test_configure_db_for_hosts(self):
        _db = "db"
        _user = "user"
        _addr = "10.10.80.80"
        _pass = "newpass"
        _json_addrs = '["10.20.10.10", "10.20.10.20", "10.20.10.30"]'
        _helper = mock.MagicMock()
        _helper.configure_db.return_value = _pass
        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        midbc.get_db_helper = mock.MagicMock()
        midbc.get_db_helper.return_value = _helper

        # One host
        self.assertEqual(
            _pass,
            midbc.configure_db_for_hosts(_addr, _db, _user))

        _helper.configure_db.assert_called_once_with(_addr, _db, _user)

        # Json multiple hosts
        _helper.reset_mock()
        _calls = [
            mock.call("10.20.10.10", _db, _user),
            mock.call("10.20.10.20", _db, _user),
            mock.call("10.20.10.30", _db, _user)]
        self.assertEqual(
            _pass,
            midbc.configure_db_for_hosts(_json_addrs, _db, _user))
        _helper.configure_db.assert_has_calls(
            _calls, any_order=True)

    def test_configure_db_router(self):
        _user = "user"
        _addr = "10.10.90.90"
        _pass = "newpass"
        _json_addrs = '["10.30.10.10", "10.30.10.20", "10.30.10.30"]'
        _helper = mock.MagicMock()
        _helper.configure_router.return_value = _pass
        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        midbc.get_db_helper = mock.MagicMock()
        midbc.get_db_helper.return_value = _helper

        # One host
        self.assertEqual(
            _pass,
            midbc.configure_db_router(_addr, _user))

        _helper.configure_router.assert_called_once_with(_addr, _user)

        # Json multiple hosts
        _helper.reset_mock()
        _calls = [
            mock.call("10.30.10.10", _user),
            mock.call("10.30.10.20", _user),
            mock.call("10.30.10.30", _user)]
        self.assertEqual(
            _pass,
            midbc.configure_db_router(_json_addrs, _user))
        _helper.configure_router.assert_has_calls(
            _calls, any_order=True)

    def test_states_to_check(self):
        self.patch_object(
            mysql_innodb_cluster.charms_openstack.charm.OpenStackCharm,
            "states_to_check", "super_states")
        self.super_states.return_value = {}
        _required_rels = ["cluster"]
        _name = "jujuCluster"
        _addr = "10.20.20.20"
        self.get_relation_ip.return_value = _addr
        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        midbc.options.cluster_name = _name
        _results = midbc.states_to_check(_required_rels)
        _states_to_check = [x[0] for x in _results["charm"]]
        self.super_states.assert_called_once_with(_required_rels)
        self.assertTrue("charm.installed" in _states_to_check)
        self.assertTrue(
            "leadership.set.cluster-instance-configured-{}".format(_addr) in
            _states_to_check)
        self.assertTrue("leadership.set.cluster-created" in _states_to_check)
        self.assertTrue(
            "leadership.set.cluster-instances-configured" in _states_to_check)
        self.assertTrue(
            "leadership.set.cluster-instance-clustered-{}".format(_addr) in
            _states_to_check)
        self.assertTrue(
            "leadership.set.cluster-instances-clustered" in _states_to_check)

    def test__assess_status(self):
        _check = mock.MagicMock()
        _check.return_value = None, None
        _conn_check = mock.MagicMock()
        _conn_check.return_value = True
        _status = mock.MagicMock()
        _status.return_value = "OK"
        self.patch_object(
            mysql_innodb_cluster.charms_openstack.charm.OpenStackCharm,
            "application_version")
        self.patch_object(
            mysql_innodb_cluster.ch_core.hookenv,
            "status_set")

        # All is well
        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        midbc.check_if_paused = _check
        midbc.check_interfaces = _check
        midbc.check_mandatory_config = _check
        midbc.check_services_running = _check
        midbc.check_mysql_connection = _conn_check
        midbc.get_cluster_status_summary = _status
        midbc.get_cluster_status_text = _status
        midbc.get_cluster_instance_mode = _status

        midbc._assess_status()
        self.assertEqual(4, len(_check.mock_calls))
        _conn_check.assert_called_once_with()
        self.assertEqual(2, len(_status.mock_calls))
        self.status_set.assert_called_once_with(
            "active", "Unit is ready: Mode: OK")

        # First checks fail
        self.status_set.reset_mock()
        _check.return_value = "blocked", "for some reason"
        midbc._assess_status()
        self.status_set.assert_called_once_with(
            "blocked", "for some reason")

        # MySQL connect fails
        self.status_set.reset_mock()
        _check.return_value = None, None
        _conn_check.return_value = False
        midbc._assess_status()
        self.status_set.assert_called_once_with(
            "blocked", "MySQL is down on this instance")

        # Cluster not healthy
        self.status_set.reset_mock()
        _status.return_value = "Cluster not healthy"
        _check.return_value = None, None
        _conn_check.return_value = True
        midbc._assess_status()
        self.status_set.assert_called_once_with(
            "blocked", "MySQL InnoDB Cluster not healthy: Cluster not healthy")

    def test_get_cluster_status(self):
        _local_addr = "10.10.50.50"
        _name = "theCluster"
        _string = "status output"
        _json_string = '"status output"'
        self.get_relation_ip.return_value = _local_addr

        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        midbc.options.cluster_name = _name
        midbc.wait_until_cluster_available = mock.MagicMock()
        midbc.run_mysqlsh_script = mock.MagicMock()
        midbc.run_mysqlsh_script.return_value = _json_string.encode("UTF-8")

        _script = """
        shell.connect("{}:{}@{}")
        var cluster = dba.getCluster("{}");

        print(cluster.status())
        """.format(
            midbc.cluster_user, midbc.cluster_password,
            midbc.cluster_address, midbc.cluster_name)

        self.assertEqual(_string, midbc.get_cluster_status())
        midbc.wait_until_cluster_available.assert_called_once()
        midbc.run_mysqlsh_script.assert_called_once_with(_script)

        # Cached data
        midbc.run_mysqlsh_script.reset_mock()
        midbc._cached_cluster_status = _string
        self.assertEqual(_string, midbc.get_cluster_status())
        midbc.run_mysqlsh_script.assert_not_called()

        # Nocache requested
        midbc.run_mysqlsh_script.reset_mock()
        midbc._cached_cluster_status = _string
        self.assertEqual(_string, midbc.get_cluster_status(nocache=True))
        midbc.run_mysqlsh_script.assert_called_once_with(_script)

    def test_get_cluster_status_summary(self):
        _status_dict = {"defaultReplicaSet": {"status": "OK"}}
        _status_obj = mock.MagicMock()
        _status_obj.return_value = _status_dict

        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        midbc.get_cluster_status = _status_obj

        self.assertEqual("OK", midbc.get_cluster_status_summary())
        _status_obj.assert_called_once_with(nocache=False)

        # Cached data
        _status_obj.reset_mock()
        midbc._cached_cluster_status = _status_dict
        self.assertEqual("OK", midbc.get_cluster_status_summary())
        _status_obj.assert_not_called()

        # Nocache requested
        _status_obj.reset_mock()
        midbc._cached_cluster_status = _status_dict
        self.assertEqual("OK", midbc.get_cluster_status_summary(nocache=True))
        _status_obj.assert_called_once_with(nocache=True)

    def test_get_cluster_status_text(self):
        _status_dict = {"defaultReplicaSet": {"statusText": "Text"}}
        _status_obj = mock.MagicMock()
        _status_obj.return_value = _status_dict

        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        midbc.get_cluster_status = _status_obj

        self.assertEqual("Text", midbc.get_cluster_status_text())
        _status_obj.assert_called_once_with(nocache=False)

        # Cached data
        _status_obj.reset_mock()
        midbc._cached_cluster_status = _status_dict
        self.assertEqual("Text", midbc.get_cluster_status_text())
        _status_obj.assert_not_called()

        # Nocache requested
        _status_obj.reset_mock()
        midbc._cached_cluster_status = _status_dict
        self.assertEqual("Text", midbc.get_cluster_status_text(nocache=True))
        _status_obj.assert_called_once_with(nocache=True)

    def test_get_cluster_instance_mode(self):
        _local_addr = "10.10.50.50"
        self.get_relation_ip.return_value = _local_addr
        _mode = "R/O"
        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        _status_dict = {
            "defaultReplicaSet":
                {"topology":
                    {"{}:{}".format(_local_addr, midbc.cluster_port):
                        {"mode": _mode}}}}
        _status_obj = mock.MagicMock()
        _status_obj.return_value = _status_dict
        midbc.get_cluster_status = _status_obj

        self.assertEqual(_mode, midbc.get_cluster_instance_mode())
        _status_obj.assert_called_once_with(nocache=False)

        # Cached data
        _status_obj.reset_mock()
        midbc._cached_cluster_status = _status_dict
        self.assertEqual(_mode, midbc.get_cluster_instance_mode())
        _status_obj.assert_not_called()

        # Nocache requested
        _status_obj.reset_mock()
        midbc._cached_cluster_status = _status_dict
        self.assertEqual(_mode, midbc.get_cluster_instance_mode(nocache=True))
        _status_obj.assert_called_once_with(nocache=True)

    def test_check_mysql_connection(self):
        self.patch_object(
            mysql_innodb_cluster.mysql.MySQLdb, "_exceptions")
        self._exceptions.OperationalError = Exception
        _helper = mock.MagicMock()
        _pass = "pass"
        _root_pass = "differentpass"
        _user = "user"
        _addr = "10.20.30.30"
        self.data = {"mysql.passwd": _root_pass}

        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        midbc.get_db_helper = mock.MagicMock()
        midbc.get_db_helper.return_value = _helper
        midbc._get_password = mock.MagicMock()
        midbc._get_password.side_effect = self._fake_data

        self.assertTrue(
            midbc.check_mysql_connection(
                username=_user, password=_pass, address=_addr))
        _helper.connect.assert_called_once_with(
            user=_user, password=_pass, host=_addr)

        _helper.reset_mock()
        _helper.connect.side_effect = self._exceptions.OperationalError
        self.assertFalse(midbc.check_mysql_connection())
        _helper.connect.assert_called_once_with(
            user="root", password=_root_pass, host="localhost")

    def test_wait_unit_connectable(self):
        _pass = "pass"
        _user = "user"
        _addr = "10.20.40.40"
        _conn_check = mock.MagicMock()

        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        midbc.check_mysql_connection = _conn_check

        # Successful connect
        _conn_check.return_value = True
        midbc.wait_until_connectable(
            username=_user, password=_pass, address=_addr)
        _conn_check.assert_called_once_with(
            username=_user, password=_pass, address=_addr)

        # Failed to connect
        _conn_check.reset_mock()
        _conn_check.return_value = False
        with self.assertRaises(mysql_innodb_cluster.CannotConnectToMySQL):
            midbc.wait_until_connectable()
        _conn_check.assert_called_once_with(
            username=None, password=None, address=None)

    def test_wait_unit_cluster_available(self):
        _name = "theCluster"
        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        midbc.options.cluster_name = _name
        midbc.run_mysqlsh_script = mock.MagicMock()
        _script = """
        shell.connect("{}:{}@{}")
        var cluster = dba.getCluster("{}");
        """.format(
            midbc.cluster_user, midbc.cluster_password,
            midbc.cluster_address, midbc.cluster_name)

        # Cluster available
        midbc.wait_until_cluster_available()
        midbc.run_mysqlsh_script.assert_called_once_with(_script)

        # Cluster not available
        midbc.run_mysqlsh_script.reset_mock()
        midbc.run_mysqlsh_script.side_effect = (Exception)
        with self.assertRaises(Exception):
            midbc.wait_until_cluster_available()
        midbc.run_mysqlsh_script.assert_called_once_with(_script)

    def test_run_mysqlsh_script(self):
        _byte_string = "UTF-8 byte string".encode("UTF-8")
        self.subprocess.check_output.return_value = _byte_string
        _script = """print("Hello World!")"""
        midbc = mysql_innodb_cluster.MySQLInnoDBClusterCharm()
        self.assertEqual(_byte_string, midbc.run_mysqlsh_script(_script))
        self.subprocess.check_output.assert_called_once_with(
            [midbc.mysqlsh_bin, "--no-wizard", "-f", self.filename],
            stderr=self.stdin)
        self.file.write.assert_called_once_with(_script)
