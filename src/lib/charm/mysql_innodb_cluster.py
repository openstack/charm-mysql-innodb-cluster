# Copyright 2019 Canonicauh Ltd
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
import subprocess
import tenacity
import tempfile
import uuid

import charms_openstack.charm
import charms_openstack.adapters

import charms.leadership as leadership
import charms.reactive as reactive

import charmhelpers.core as ch_core
import charmhelpers.contrib.network.ip as ch_net_ip

import charmhelpers.contrib.database.mysql as mysql


MYSQLD_CNF = "/etc/mysql/mysql.conf.d/mysqld.cnf"


@charms_openstack.adapters.config_property
def server_id(cls):
    unit_num = int(ch_core.hookenv.local_unit().split("/")[1])
    return str(unit_num + 1000)


@charms_openstack.adapters.config_property
def cluster_address(cls):
    return ch_net_ip.get_relation_ip("cluster")


@charms_openstack.adapters.config_property
def shared_db_address(cls):
    return ch_net_ip.get_relation_ip("shared-db")


@charms_openstack.adapters.config_property
def db_router_address(cls):
    return ch_net_ip.get_relation_ip("db-router")


class CannotConnectToMySQL(Exception):
    pass


class MySQLInnoDBClusterCharm(charms_openstack.charm.OpenStackCharm):
    """Charm class for the MySQLInnoDBCluster charm."""
    name = "mysql"
    release = "stein"
    # TODO: Current versions of the mysql-shell snap require libpython2.7
    # This will not be available in 20.04
    # Fix the mysql-shell snap and remove the package here
    packages = ["mysql-router", "mysql-server-8.0", "python3-dnspython",
                "libpython2.7"]
    python_version = 3
    default_service = "mysql"
    services = ["mysql"]
    restart_map = {
        MYSQLD_CNF: services,
    }
    release_pkg = "mysql-server"
    group = "mysql"
    required_relations = ["cluster"]
    source_config_key = "source"

    # For internal use with get_db_data
    _unprefixed = "MICUP"

    @property
    def mysqlsh_bin(self):
        # The current upstream snap uses mysql-shell
        # When we get the alias use /snap/bin/mysqlsh
        # return "/snap/bin/mysqlsh"
        return "/snap/mysql-shell/current/usr/bin/mysqlsh"

    def install(self):
        """Custom install function.
        """

        # Set mysql password in packaging before installation
        self.configure_mysql_password()

        # TODO: charms.openstack should probably do this
        # Need to configure source first
        self.configure_source()
        super().install()

        # Render mysqld.cnf and cause a restart
        self.render_all_configs()

    def get_db_helper(self):
        return mysql.MySQL8Helper(
            rpasswdf_template="/var/lib/charm/{}/mysql.passwd"
                              .format(ch_core.hookenv.service_name()),
            upasswdf_template="/var/lib/charm/{}/mysql-{{}}.passwd"
                              .format(ch_core.hookenv.service_name()))

    def create_cluster_user(
            self, cluster_address, cluster_user, cluster_password):

        SQL_REMOTE_CLUSTER_USER_CREATE = (
            "CREATE USER '{user}'@'{host}' "
            "IDENTIFIED BY '{password}'")

        SQL_LOCAL_CLUSTER_USER_CREATE = (
            "CREATE USER '{user}'@'localhost' "
            "IDENTIFIED BY '{password}'")

        SQL_CLUSTER_USER_GRANT = (
            "GRANT {permissions} ON *.* "
            "TO 'clusteruser'@'{host}'")

        m_helper = self.get_db_helper()
        m_helper.connect(password=self.mysql_password)
        try:
            m_helper.execute(SQL_REMOTE_CLUSTER_USER_CREATE.format(
                user=cluster_user,
                host=cluster_address,
                password=cluster_password)
            )
        except mysql.MySQLdb._exceptions.OperationalError:
            ch_core.hookenv.log("Remote user {} already exists."
                                .format(cluster_user), "WARNING")

        if cluster_address in self.cluster_address:
            try:
                m_helper.execute(SQL_LOCAL_CLUSTER_USER_CREATE.format(
                    user=cluster_user,
                    password=cluster_password)
                )
            except mysql.MySQLdb._exceptions.OperationalError:
                ch_core.hookenv.log("Local user {} already exists."
                                    .format(cluster_user), "WARNING")

        m_helper.execute(SQL_CLUSTER_USER_GRANT.format(
            permissions="ALL PRIVILEGES",
            user=cluster_user,
            host=cluster_address)
        )
        m_helper.execute(SQL_CLUSTER_USER_GRANT.format(
            permissions="GRANT OPTION",
            user=cluster_user,
            host=cluster_address)
        )

        m_helper.execute("flush privileges")

    def configure_db_for_hosts(self, hosts, database, username):
        """Hosts may be a json-encoded list of hosts or a single hostname."""
        if not all([hosts, database, username]):
            ch_core.hookenv.log("Remote data incomplete.", "WARNING")
            return
        try:
            hosts = json.loads(hosts)
            ch_core.hookenv.log("Multiple hostnames provided by relation: {}"
                                .format(', '.join(hosts)), "DEBUG")
        except ValueError:
            ch_core.hookenv.log(
                "Single hostname provided by relation: {}".format(hosts),
                level="DEBUG")
            hosts = [hosts]

        db_helper = self.get_db_helper()

        for host in hosts:
            password = db_helper.configure_db(host, database, username)

        return password

    def configure_db_router(self, hosts, username):
        """Hosts may be a json-encoded list of hosts or a single hostname."""
        if not all([hosts, username]):
            ch_core.hookenv.log("Remote data incomplete.", "WARNING")
            return
        try:
            hosts = json.loads(hosts)
            ch_core.hookenv.log("Multiple hostnames provided by relation: {}"
                                .format(', '.join(hosts)), "DEBUG")
        except ValueError:
            ch_core.hookenv.log(
                "Single hostname provided by relation: {}".format(hosts),
                level="DEBUG")
            hosts = [hosts]

        db_helper = self.get_db_helper()

        for host in hosts:
            password = db_helper.configure_router(host, username)

        return password

    def _get_password(self, key):
        """Retrieve named password

        This function will ensure that a consistent named password
        is used across all units in the InnoDB cluster; the lead unit
        will generate or use the mysql.passwd configuration option
        to seed this value into the deployment.

        Once set, it cannot be changed.

        @requires: str: named password or None if unable to retrieve
                        at this point in time
        """
        _password = ch_core.hookenv.leader_get(key)
        if not _password and ch_core.hookenv.is_leader():
            _password = ch_core.hookenv.config(key) or ch_core.host.pwgen()
            ch_core.hookenv.leader_set({key: _password})
        return _password

    @property
    def mysql_password(self):
        return self._get_password("mysql.passwd")

    @property
    def cluster_password(self):
        return self._get_password("cluster-password")

    @property
    def cluster_address(self):
        return self.options.cluster_address

    @property
    def cluster_user(self):
        return "clusteruser"

    @property
    def shared_db_address(self):
        return self.options.shared_db_address

    @property
    def db_router_address(self):
        return self.options.db_router_address

    def configure_instance(self, address):

        if reactive.is_flag_set(
                "leadership.set.cluster-instance-configured-{}"
                .format(address)):
            ch_core.hookenv.log("Instance: {}, already configured."
                                .format(address), "WARNING")
            return

        ch_core.hookenv.log("Configuring instance for clustering: {}."
                            .format(address), "INFO")
        _script_template = """
        dba.configureInstance('{}:{}@{}');
        var myshell = shell.connect('{}:{}@{}');
        myshell.runSql("RESTART;");
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".js") as _script:
            _script.write(_script_template.format(
                self.cluster_user, self.cluster_password, address,
                self.cluster_user, self.cluster_password, address))
            _script.flush()

            cmd = ([self.mysqlsh_bin, "--no-wizard", "-f", _script.name])
            try:
                output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                ch_core.hookenv.log(
                    "Failed configuring instance {}: {}"
                    .format(address, e.output.decode("UTF-8")), "ERROR")
                return

        # After configuration of the remote instance, the remote instance
        # restarts mysql. We need to pause here for that to complete.
        self._wait_until_connectable(username=self.cluster_user,
                                     password=self.cluster_password,
                                     address=address)

        ch_core.hookenv.log("Instance Configured {}: {}"
                            .format(address, output.decode("UTF-8")),
                            level="DEBUG")
        leadership.leader_set({"cluster-instance-configured-{}"
                               .format(address): True})

    @property
    def cluster_name(self):
        return self.options.cluster_name

    def create_cluster(self):

        if reactive.is_flag_set("leadership.set.cluster-created"):
            ch_core.hookenv.log("Cluster: {}, already created"
                                .format(self.options.cluster_name), "WARNING")
            return

        if not reactive.is_flag_set(
                "leadership.set.cluster-instance-configured-{}"
                .format(self.cluster_address)):
            ch_core.hookenv.log("This instance is not yet configured for "
                                "clustering, delaying cluster creation.",
                                "WARNING")
            return

        _script_template = """
        shell.connect("{}:{}@{}")
        var cluster = dba.createCluster("{}");
        """

        ch_core.hookenv.log("Creating cluster: {}."
                            .format(self.options.cluster_name), "INFO")
        with tempfile.NamedTemporaryFile(mode="w", suffix=".js") as _script:
            _script.write(_script_template.format(
                self.cluster_user, self.cluster_password, self.cluster_address,
                self.options.cluster_name,
                self.cluster_user,
                self.cluster_address,
                self.cluster_password))
            _script.flush()

            cmd = ([self.mysqlsh_bin, "--no-wizard", "-f", _script.name])
            try:
                output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                ch_core.hookenv.log(
                    "Failed creating cluster: {}"
                    .format(e.output.decode("UTF-8")), "ERROR")
                return
        ch_core.hookenv.log("Cluster Created: {}"
                            .format(output.decode("UTF-8")),
                            level="DEBUG")
        leadership.leader_set({"cluster-instance-clustered-{}"
                               .format(self.cluster_address): True})
        leadership.leader_set({"cluster-created": str(uuid.uuid4())})

    def add_instance_to_cluster(self, address):

        if reactive.is_flag_set(
                "leadership.set.cluster-instance-clustered-{}"
                .format(address)):
            ch_core.hookenv.log("Instance: {}, already clustered."
                                .format(address), "WARNING")
            return

        ch_core.hookenv.log("Adding instance, {}, to the cluster."
                            .format(address), "INFO")
        _script_template = """
        shell.connect("{}:{}@{}")
        var cluster = dba.getCluster("{}");

        print("Adding instances to the cluster.");
        cluster.addInstance(
            {{user: "{}", host: "{}", password: "{}", port: "3306"}},
            {{recoveryMethod: "clone"}});
        """

        with tempfile.NamedTemporaryFile(mode="w", suffix=".js") as _script:
            _script.write(_script_template.format(
                self.cluster_user, self.cluster_password, self.cluster_address,
                self.options.cluster_name,
                self.cluster_user, address, self.cluster_password))
            _script.flush()

            cmd = ([self.mysqlsh_bin, "--no-wizard", "-f", _script.name])
            try:
                output = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            except subprocess.CalledProcessError as e:
                ch_core.hookenv.log(
                    "Failed adding instance {} to cluster: {}"
                    .format(address, e.output.decode("UTF-8")), "ERROR")
                return
        ch_core.hookenv.log("Instance Clustered {}: {}"
                            .format(address, output.decode("UTF-8")),
                            level="DEBUG")
        leadership.leader_set({"cluster-instance-clustered-{}"
                               .format(address): True})

    def states_to_check(self, required_relations=None):
        """Custom state check function for charm specific state check needs.

        """
        states_to_check = super().states_to_check(required_relations)
        states_to_check["charm"] = [
            ("charm.installed",
             "waiting",
             "MySQL not installed"),
            ("leadership.set.cluster-instance-configured-{}"
             .format(self.cluster_address),
             "waiting",
             "Instance not yet configured for clustering"),
            ("leadership.set.cluster-created",
             "waiting",
             "Cluster {} not yet created by leader"
             .format(self.cluster_name)),
            ("leadership.set.cluster-instances-configured",
             "waiting",
             "Not all instances configured for clustering"),
            ("leadership.set.cluster-instance-clustered-{}"
             .format(self.cluster_address),
             "waiting",
             "Instance not yet in the cluster"),
            ("leadership.set.cluster-instances-clustered",
             "waiting",
             "Not all instances clustered")]

        return states_to_check

    def check_mysql_connection(
            self, username=None, password=None, address=None):
        """Check if local instance of mysql is accessible.

        Attempt a connection to the local instance of mysql to determine if it
        is running and accessible.

        :param password: Password to use for connection test.
        :type password: str
        :side effect: Uses get_db_helper to execute a connection to the DB.
        :returns: boolean
        """
        address = address or "localhost"
        password = password or self.mysql_password
        username = username or "root"

        m_helper = self.get_db_helper()
        try:
            m_helper.connect(user=username, password=password, host=address)
            return True
        except mysql.MySQLdb._exceptions.OperationalError:
            ch_core.hookenv.log("Could not connect to db", "DEBUG")
            return False

    @tenacity.retry(wait=tenacity.wait_fixed(10),
                    reraise=True,
                    stop=tenacity.stop_after_delay(5))
    def _wait_until_connectable(
            self, username=None, password=None, address=None):

        if not self.check_mysql_connection(
                username=username, password=password, address=address):
            raise CannotConnectToMySQL("Unable to connect to MySQL")

    def custom_assess_status_check(self):

        # Start with default checks
        for f in [self.check_if_paused,
                  self.check_interfaces,
                  self.check_mandatory_config]:
            state, message = f()
            if state is not None:
                ch_core.hookenv.status_set(state, message)
                return state, message

        # We should not get here until there is a connection to the
        # cluster
        if not self.check_mysql_connection():
            return "blocked", "MySQL is down"

        return None, None

    # TODO: move to mysql charmhelper
    def configure_mysql_password(self):
        """ Configure debconf with mysql password """
        dconf = subprocess.Popen(
            ['debconf-set-selections'], stdin=subprocess.PIPE)
        # Set password options to cover packages
        packages = ["mysql-server", "mysql-server-8.0"]
        for package in packages:
            dconf.stdin.write("{} {}/root_password password {}\n"
                              .format(package, package, self.mysql_password)
                              .encode("utf-8"))
            dconf.stdin.write("{} {}/root_password_again password {}\n"
                              .format(package, package, self.mysql_password)
                              .encode("utf-8"))
        dconf.communicate()
        dconf.wait()

    # TODO: move to mysql charmhelper
    def get_allowed_units(self, database, username, relation_id):
        db_helper = self.get_db_helper()
        allowed_units = db_helper.get_allowed_units(
            database, username, relation_id=relation_id)
        allowed_units = sorted(
            allowed_units, key=lambda a: int(a.split('/')[-1]))
        allowed_units = ' '.join(allowed_units)
        return allowed_units

    # TODO: move to mysql charmhelper
    def resolve_hostname_to_ip(self, hostname):
        """Resolve hostname to IP

        @param hostname: hostname to be resolved
        @returns IP address or None if resolution was not possible via DNS
        """
        import dns.resolver

        if self.options.prefer_ipv6:
            if ch_net_ip.is_ipv6(hostname):
                return hostname

            query_type = 'AAAA'
        elif ch_net_ip.is_ip(hostname):
            return hostname
        else:
            query_type = 'A'

        # This may throw an NXDOMAIN exception; in which case
        # things are badly broken so just let it kill the hook
        answers = dns.resolver.query(hostname, query_type)
        if answers:
            return answers[0].address

    def create_databases_and_users(self, interface):
        """Create databases and users

        :param interface: Relation data
        :type interface: reative.relations.Endpoint object
        :side effect: interface.set_db_connection_info is exectuted
        :returns: None
        :rtype: None
        """
        for unit in interface.all_joined_units:

            db_data = mysql.get_db_data(
                dict(unit.received),
                unprefixed=self._unprefixed)

            db_host = ch_net_ip.get_relation_ip(interface.endpoint_name)
            mysqlrouterset = {'username', 'hostname'}
            singleset = {'database', 'username', 'hostname'}

            for prefix in db_data:
                if singleset.issubset(db_data[prefix]):
                    database = db_data[prefix]['database']
                    hostname = db_data[prefix]['hostname']
                    username = db_data[prefix]['username']

                    password = self.configure_db_for_hosts(
                        hostname, database, username)

                    allowed_units = self.get_allowed_units(
                        database, username,
                        unit.relation.relation_id)

                    if prefix in self._unprefixed:
                        prefix = None

                elif mysqlrouterset.issubset(db_data[prefix]):
                    hostname = db_data[prefix]['hostname']
                    username = db_data[prefix]['username']

                    password = self.configure_db_router(hostname, username)
                    allowed_units = " ".join(
                        [x.unit_name for x in unit.relation.joined_units])

                interface.set_db_connection_info(
                    unit.relation.relation_id,
                    db_host,
                    password,
                    allowed_units=allowed_units, prefix=prefix)
