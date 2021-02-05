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

import base64
import datetime
import json
import os
import subprocess
import tenacity
import tempfile
import uuid

import charms.coordinator as coordinator
import charms_openstack.charm
import charms_openstack.adapters

import charms.leadership as leadership
import charms.reactive as reactive

import charmhelpers.core as ch_core
import charmhelpers.contrib.network.ip as ch_net_ip
import charmhelpers.contrib.openstack.cert_utils as cert_utils

import charmhelpers.contrib.database.mysql as mysql

from charms_openstack.charm import utils as chos_utils


MYSQLD_CNF = "/etc/mysql/mysql.conf.d/mysqld.cnf"


@charms_openstack.adapters.config_property
def server_id(cls):
    """Determine this unit's server ID.

    :param cls: Class
    :type cls: ConfigurationAdapter class
    :returns: String server ID
    :rtype: str
    """
    unit_num = int(ch_core.hookenv.local_unit().split("/")[1])
    return str(unit_num + 1000)


@charms_openstack.adapters.config_property
def cluster_address(cls):
    """Determine this unit's cluster address.

    Using the relation binding determine this unit's cluster address.

    :param cls: Class
    :type cls: ConfigurationAdapter class
    :returns: Address
    :rtype: str
    """
    return ch_net_ip.get_relation_ip("cluster")


@charms_openstack.adapters.config_property
def shared_db_address(cls):
    """Determine this unit's Shared-DB address.

    Using the relation binding determine this unit's address for the Shared-DB
    relation.

    :param cls: Class
    :type cls: ConfigurationAdapter class
    :returns: Address
    :rtype: str
    """
    return ch_net_ip.get_relation_ip("shared-db")


@charms_openstack.adapters.config_property
def db_router_address(cls):
    """Determine this unit's DB-Router address.

    Using the relation binding determine this unit's address for the DB-Router
    relation.

    :param cls: Class
    :type cls: ConfigurationAdapter class
    :returns: Address
    :rtype: str
    """
    return ch_net_ip.get_relation_ip("db-router")


@charms_openstack.adapters.config_property
def innodb_flush_log_at_trx_commit_adapter(cls):
    """Determine the value for innodb_flush_log_at_trx_commit.

    Call the MySQLConfigHelper get_innodb_flush_log_at_trx_commit helper to get
    the value for innodb_flush_log_at_trx_commit.

    :param cls: Class
    :type cls: ConfigurationAdapter class
    :returns: Numeric innodb_flush_log_at_trx_commit value
    :rtype: int
    """
    return mysql.get_mysql_config_helper().get_innodb_flush_log_at_trx_commit()


@charms_openstack.adapters.config_property
def innodb_change_buffering_adapter(cls):
    """Determine the value for innodb_flush_log_at_trx_commit.

    Call the MySQLConfigHelper get_innodb_change_buffering helper to get the
    value for innodb_change_buffering.

    :param cls: Class
    :type cls: ConfigurationAdapter class
    :returns: string innodb_change_buffering value
    :rtype: str
    """
    return mysql.get_mysql_config_helper().get_innodb_change_buffering()


@charms_openstack.adapters.config_property
def innodb_buffer_pool_size_adapter(cls):
    """Determine the value for innodb_flush_log_at_trx_commit.

    Call the MySQLConfigHelper innodb_buffer_pool_size helper to get the value
    for innodb_buffer_pool_size_adapter.

    :param cls: Class
    :type cls: ConfigurationAdapter class
    :returns: Numeric innodb_buffer_pool_size value
    :rtype: int
    """
    return mysql.get_mysql_config_helper().get_innodb_buffer_pool_size()


@charms_openstack.adapters.config_property
def binlog_expire_logs_seconds_adapter(cls):
    """Determine the value for binlog_expire_logs_seconds.

    From the binlogs-expire-days config option calculate the number of seconds.

    :param cls: Class
    :type cls: ConfigurationAdapter class
    :returns: Numeric binlog_expire_logs_seconds value
    :rtype: int
    """
    days = int(ch_core.hookenv.config("binlogs-expire-days"))
    return 60 * 60 * 24 * days


@charms_openstack.adapters.config_property
def tls_enabled(cls):
    return reactive.is_flag_set("tls.enabled")


class CannotConnectToMySQL(Exception):
    """Exception when attempting to connect to a MySQL server.
    """
    pass


class MySQLInnoDBClusterCharm(charms_openstack.charm.OpenStackCharm):
    """Charm class for the MySQLInnoDBCluster charm."""
    name = "mysql-innodb-cluster"
    release = "train"
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

    # For caching cluster status information
    _cached_cluster_status = None

    _read_only_error = 1290
    _user_create_failed = 1396

    @property
    def mysqlsh_bin(self):
        """Determine binary path for MySQL Shell.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :returns: Path to binary mysqlsh
        :rtype: str
        """
        # Allow for various versions of the msyql-shell snap
        # When we get the alias use /snap/bin/mysqlsh
        if os.path.exists("/snap/bin/mysqlsh"):
            return "/snap/bin/mysqlsh"
        if os.path.exists("/snap/bin/mysql-shell.mysqlsh"):
            return "/snap/bin/mysql-shell.mysqlsh"
        # Default to the full path version
        return "/snap/bin/mysql-shell"

    @property
    def mysqlsh_common_dir(self):
        """Determine snap common dir for mysqlsh

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :returns: Path to common dir
        :rtype: str
        """
        return "/root/snap/mysql-shell/common"

    @property
    def mysql_password(self):
        """Determine or set primary MySQL password.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :returns: MySQL password
        :rtype: str
        """
        return self._get_password("mysql.passwd")

    @property
    def cluster_name(self):
        """Determine the MySQL InnoDB Cluster name.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :returns: Cluster name
        :rtype: str
        """
        return self.options.cluster_name

    @property
    def cluster_password(self):
        """Determine or set password for the cluster user.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :returns: Cluster password
        :rtype: str
        """
        return self._get_password("cluster-password")

    @property
    def cluster_address(self):
        """Determine this unit's cluster address.

        Using the class method determine this unit's cluster address.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :returns: Address
        :rtype: str
        """
        return self.options.cluster_address

    @property
    def cluster_port(self):
        """Determine this unit's cluster port.

        Using the class method determine this unit's cluster address.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :returns: Port
        :rtype: str
        """
        return "3306"

    @property
    def cluster_user(self):
        """Determine the cluster username.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :returns: Cluster username
        :rtype: str
        """
        return "clusteruser"

    @property
    def cluster_relation_endpoint(self):
        """Determine the cluster username.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :returns: Cluster username
        :rtype: str
        """
        return reactive.endpoint_from_flag("cluster.available")

    @property
    def shared_db_address(self):
        """Determine this unit's Shared-DB address.

        Using the class method determine this unit's address for the Shared-DB
        relation.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :returns: Address
        :rtype: str
        """
        return self.options.shared_db_address

    @property
    def db_router_address(self):
        """Determine this unit's Shared-DB address.

        Using the class method determine this unit's address for the DB-Router
        relation.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :returns: Address
        :rtype: str
        """
        return self.options.db_router_address

    @property
    def ssl_ca(self):
        """Return the SSL Certificate Authority

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :returns: Cluster username
        :rtype: str
        """
        if self.options.ssl_ca:
            return self.options.ssl_ca
        _certificates = (
            reactive.endpoint_from_flag("certificates.available"))
        if (_certificates and _certificates.root_ca_cert and
                _certificates.root_ca_chain):
            _cert_chain = (
                _certificates.root_ca_cert + os.linesep +
                _certificates.root_ca_chain)
            return base64.b64encode(_cert_chain.encode("UTF-8")).decode()

    # TODO: Generalize and move to mysql charmhelpers
    def _get_password(self, key):
        """Retrieve named password.

        This function will ensure that a consistent named password
        is used across all units in the InnoDB cluster.

        The lead unit will generate or use the mysql.passwd configuration
        option to seed this value into the deployment.

        Once set, it cannot be changed.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :param key: Named password or None if unable to retrieve at this point
                    in time
        :type key: str
        :returns: Address
        :rtype: str
        """
        _password = ch_core.hookenv.leader_get(key)
        if not _password and ch_core.hookenv.is_leader():
            _password = ch_core.hookenv.config(key) or ch_core.host.pwgen()
            ch_core.hookenv.leader_set({key: _password})
        return _password

    # TODO: Generalize and move to mysql charmhelpers
    def configure_mysql_password(self):
        """ Configure debconf with mysql password.

        Prior to installation set the root-password for the MySQL server
        package(s).

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :side effect: Executes debconf
        :returns: This function is called for its side effect
        :rtype: None
        """
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

    def install(self):
        """Custom install function.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :side effect: Executes other functions
        :returns: This function is called for its side effect
        :rtype: None
        """
        # Set mysql password in packaging before installation
        self.configure_mysql_password()

        # TODO: charms.openstack should probably do this
        # Need to configure source first
        self.configure_source()
        super().install()

        # Check for TLS config
        self.configure_tls()

        # Render mysqld.cnf and cause a restart
        self.render_all_configs()

    # TODO: Generalize and move to mysql charmhelpers
    def get_db_helper(self):
        """Get an instance of the MySQLDB8Helper class.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :returns: Instance of MySQLDB8Helper class
        :rtype: MySQLDB8Helper instance
        """
        # NOTE: The template paths are an artifact of the original Helper code.
        # Passwords are injected into leader settings. No passwords are written
        # to disk by this class.
        return mysql.MySQL8Helper(
            rpasswdf_template="/var/lib/charm/{}/mysql.passwd"
                              .format(ch_core.hookenv.service_name()),
            upasswdf_template="/var/lib/charm/{}/mysql-{{}}.passwd"
                              .format(ch_core.hookenv.service_name()))

    def get_cluster_rw_db_helper(self):
        """Get connected RW instance of the MySQLDB8Helper class.

        Connect to the RW cluster primary node and return a DB helper.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :returns: Instance of MySQLDB8Helper class
        :rtype: Union[None, MySQLDB8Helper]
        """
        _primary = self.get_cluster_primary_address(nocache=True)
        if not _primary:
            ch_core.hookenv.log(
                "Cannot determine the cluster primary RW node for writes.",
                "WARNING")
            return
        _helper = self.get_db_helper()
        _helper.connect(
            user=self.cluster_user,
            password=self.cluster_password,
            host=self.get_cluster_primary_address(nocache=True))
        return _helper

    def create_cluster_user(
            self, cluster_address, cluster_user, cluster_password):
        """Create cluster user and grant permissions in the MySQL DB.

        This user will be used by the leader for instance configuration and
        initial cluster creation.

        The grants are specfic to cluster creation and management as documented
        upstream.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :param cluster_address: Cluster user's address
        :type cluster_address: str
        :param cluster_user: Cluster user's username
        :type cluster_user: str
        :param cluster_password: Cluster user's password
        :type cluster_password: str
        :side effect: Executes SQL to create DB user
        :returns: True if successful, False if there are failures
        :rtype: Boolean
        """
        SQL_CLUSTER_USER_CREATE = (
            "CREATE USER '{user}'@'{host}' "
            "IDENTIFIED BY '{password}'")

        SQL_CLUSTER_USER_GRANT = (
            "GRANT {permissions} ON *.* "
            "TO '{user}'@'{host}'")

        addresses = [cluster_address]
        if cluster_address in self.cluster_address:
            addresses.append("localhost")

        # If this is scale out and the cluster already exists, use the cluster
        # RW node for writes.
        m_helper = self.get_cluster_rw_db_helper()
        if not m_helper:
            m_helper = self.get_db_helper()
            m_helper.connect(password=self.mysql_password)

        for address in addresses:
            try:
                m_helper.execute(SQL_CLUSTER_USER_CREATE.format(
                    user=cluster_user,
                    host=address,
                    password=cluster_password)
                )
                m_helper.execute(SQL_CLUSTER_USER_GRANT.format(
                    permissions="ALL PRIVILEGES",
                    user=cluster_user,
                    host=address)
                )
                m_helper.execute(SQL_CLUSTER_USER_GRANT.format(
                    permissions="GRANT OPTION",
                    user=cluster_user,
                    host=address)
                )

                m_helper.execute("flush privileges")
            except mysql.MySQLdb._exceptions.OperationalError as e:
                if e.args[0] == self._read_only_error:
                    ch_core.hookenv.log(
                        "Attempted to write to the RO node: {} in "
                        "configure_db_for_hosts. Skipping."
                        .format(m_helper.connection.get_host_info()),
                        "WARNING")
                    return False
                if e.args[0] == self._user_create_failed:
                    ch_core.hookenv.log(
                        "User {} exists."
                        .format(cluster_user), "WARNING")
                    continue
                else:
                    raise
        return True

    def configure_instance(self, address):
        """Configure MySQL instance for clustering.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :param address: Address of the MySQL instance to be configured
        :type address: str
        :side effect: Calls self.run_mysqlsh_script
        :returns: This function is called for its side effect
        :rtype: None
        """
        if reactive.is_flag_set(
                "leadership.set.cluster-instance-configured-{}"
                .format(address)):
            ch_core.hookenv.log("Instance: {}, already configured."
                                .format(address), "WARNING")
            return

        ch_core.hookenv.log("Configuring instance for clustering: {}."
                            .format(address), "INFO")
        _script = (
            "dba.configure_instance('{user}:{pw}@{addr}')\n"
            .format(
                user=self.cluster_user,
                pw=self.cluster_password,
                addr=address))
        try:
            output = self.run_mysqlsh_script(_script)
        except subprocess.CalledProcessError as e:
            ch_core.hookenv.log(
                "Failed configuring instance {}: {}"
                .format(address, e.stderr.decode("UTF-8")), "ERROR")
            return

        # After configuration of the remote instance, the remote instance
        # restarts mysql. We need to pause here for that to complete.
        self.wait_until_connectable(username=self.cluster_user,
                                    password=self.cluster_password,
                                    address=address)

        ch_core.hookenv.log("Instance Configured {}: {}"
                            .format(address, output.decode("UTF-8")),
                            level="DEBUG")
        leadership.leader_set({"cluster-instance-configured-{}"
                               .format(address): True})

    def create_cluster(self):
        """Create the MySQL InnoDB cluster.

        Creates the MySQL InnoDB cluster using self.cluster_name.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :side effect: Calls self.run_mysqlsh_script
        :returns: This function is called for its side effect
        :rtype: None
        """
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

        _script = (
            "shell.connect('{}:{}@{}')\n"
            "cluster = dba.create_cluster('{}', {{'autoRejoinTries': '{}', "
            "'expelTimeout': '{}'}})"
            .format(
                self.cluster_user, self.cluster_password, self.cluster_address,
                self.options.cluster_name, self.options.auto_rejoin_tries,
                self.options.expel_timeout
            ))
        ch_core.hookenv.log("Creating cluster: {}."
                            .format(self.options.cluster_name), "INFO")
        try:
            output = self.run_mysqlsh_script(_script)
        except subprocess.CalledProcessError as e:
            ch_core.hookenv.log(
                "Failed creating cluster: {}"
                .format(e.stderr.decode("UTF-8")), "ERROR")
            return
        ch_core.hookenv.log("Cluster Created: {}"
                            .format(output.decode("UTF-8")),
                            level="DEBUG")
        leadership.leader_set({"cluster-instance-clustered-{}"
                               .format(self.cluster_address): True})
        leadership.leader_set({"cluster-created": str(uuid.uuid4())})

    def set_cluster_option(self, key, value):
        """Set an option on the cluster

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :param key: Option name
        :type key: str
        :param value: Option value
        :type value: str
        :side effect: Calls self.run_mysqlsh_script
        :returns: This function is called for its side effect
        :rtype: None
        """
        _primary = self.get_cluster_primary_address(nocache=True)
        _script = (
            "shell.connect('{}:{}@{}')\n"
            "cluster = dba.get_cluster('{}')\n"
            "cluster.set_option('{}', {})"
            .format(
                self.cluster_user, self.cluster_password,
                _primary or self.cluster_address,
                self.options.cluster_name, key, value))
        try:
            output = self.run_mysqlsh_script(_script).decode("UTF-8")
            return output
        except subprocess.CalledProcessError as e:
            ch_core.hookenv.log(
                "Failed setting cluster option {}={}: {}"
                .format(key, value, e.stderr.decode("UTF-8")),
                "ERROR")
            # Reraise for action handling
            raise e

    def add_instance_to_cluster(self, address):
        """Add MySQL instance to the cluster.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :param address: Address of the MySQL instance to be clustered
        :type address: str
        :side effect: Calls self.run_mysqlsh_script
        :returns: This function is called for its side effect
        :rtype: None
        """
        if reactive.is_flag_set(
                "leadership.set.cluster-instance-clustered-{}"
                .format(address)):
            ch_core.hookenv.log("Instance: {}, already clustered."
                                .format(address), "WARNING")
            return

        _primary = self.get_cluster_primary_address(nocache=True)
        ch_core.hookenv.log("Adding instance, {}, to the cluster."
                            .format(address), "INFO")
        _script = (
            "shell.connect('{user}:{pw}@{caddr}')\n"
            "cluster = dba.get_cluster('{name}')\n"
            "cluster.add_instance("
            "{{'user': '{user}', 'host': '{addr}', 'password': '{pw}', "
            "'port': '3306'}},"
            "{{'recoveryMethod': 'clone'}})"
            .format(
                user=self.cluster_user, pw=self.cluster_password,
                caddr=_primary or self.cluster_address,
                name=self.options.cluster_name, addr=address))
        try:
            output = self.run_mysqlsh_script(_script)
        except subprocess.CalledProcessError as e:
            ch_core.hookenv.log(
                "Failed adding instance {} to cluster: {}"
                .format(address, e.stderr.decode("UTF-8")), "ERROR")
            return
        ch_core.hookenv.log("Instance Clustered {}: {}"
                            .format(address, output.decode("UTF-8")),
                            level="DEBUG")
        leadership.leader_set({"cluster-instance-clustered-{}"
                               .format(address): True})

    def restart_instance(self, address):
        """Restart instance

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :param address: Address of the MySQL instance to be configured
        :type address: str
        :side effect: Calls self.run_mysqlsh_script
        :returns: This function is called for its side effect
        :rtype: None
        """
        ch_core.hookenv.log("Restarting instance: {}.".format(address), "INFO")
        _server_gone_away_error = "MySQL Error (2006)"
        _script = (
            "myshell = shell.connect('{user}:{pw}@{addr}')\n"
            "myshell.run_sql('RESTART;')"
            .format(
                user=self.cluster_user,
                pw=self.cluster_password,
                addr=address))
        try:
            output = self.run_mysqlsh_script(_script)
        except subprocess.CalledProcessError as e:
            # If the shell reports the server went away we expect this
            # when giving the RESTART command
            if _server_gone_away_error not in e.stderr.decode("UTF-8"):
                ch_core.hookenv.log(
                    "Failed restarting instance {}: {}"
                    .format(address, e.stderr.decode("UTF-8")), "ERROR")
                raise e

        # After configuration of the remote instance, the remote instance
        # restarts mysql. We need to pause here for that to complete.
        self.wait_until_connectable(username=self.cluster_user,
                                    password=self.cluster_password,
                                    address=address)

        ch_core.hookenv.log("Instance restarted {}: {}"
                            .format(address, output.decode("UTF-8")),
                            level="DEBUG")

    def reboot_cluster_from_complete_outage(self):
        """Reboot cluster from complete outage.

        Execute the dba.reboot_cluster_from_complete_outage() after an outage.
        This will rebootstrap the cluster and join this instance to the
        previously existing cluster.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :side effect: Calls self.run_mysqlsh_script
        :returns: This function is called for its side effect
        :rtype: None
        """
        _script = (
            "shell.connect('{}:{}@{}')\n"
            "dba.reboot_cluster_from_complete_outage()"
            .format(
                self.cluster_user, self.cluster_password,
                self.cluster_address))
        try:
            output = self.run_mysqlsh_script(_script).decode("UTF-8")
            ch_core.hookenv.log(
                "Reboot cluster from complete outage successful: "
                "{}".format(output),
                level="DEBUG")
            return output
        except subprocess.CalledProcessError as e:
            ch_core.hookenv.log(
                "Failed rebooting from complete outage: {}"
                .format(e.stderr.decode("UTF-8")),
                "ERROR")
            # Reraise for action handling
            raise e

    def rejoin_instance(self, address):
        """Rejoin instance to the cluster

        Execute the cluster.rejoin_instance(address) to rejoin the specified
        instance to the cluster.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :side effect: Calls self.run_mysqlsh_script
        :returns: This function is called for its side effect
        :rtype: None
        """
        _primary = self.get_cluster_primary_address(nocache=True)
        ch_core.hookenv.log("Rejoin instance: {}.".format(address))
        _script = (
            "shell.connect('{user}:{pw}@{caddr}')\n"
            "cluster = dba.get_cluster('{name}')\n"
            "cluster.rejoin_instance('{user}:{pw}@{addr}')"
            .format(
                user=self.cluster_user, pw=self.cluster_password,
                caddr=_primary or self.cluster_address,
                name=self.cluster_name, addr=address))
        try:
            output = self.run_mysqlsh_script(_script).decode("UTF-8")
            ch_core.hookenv.log(
                "Rejoin instance {} successful: "
                "{}".format(address, output),
                level="DEBUG")
            return output
        except subprocess.CalledProcessError as e:
            ch_core.hookenv.log(
                "Failed rejoining instance {}: {}"
                .format(address, e.stderr.decode("UTF-8")),
                "ERROR")
            # Reraise for action handling
            raise e

    def remove_instance(self, address, force=False):
        """Remove instance from the cluster

        Execute the cluster.remove_instance(address) to remove an instance from
        the cluster.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :side effect: Calls self.run_mysqlsh_script
        :returns: This function is called for its side effect
        :rtype: None
        """
        _primary = self.get_cluster_primary_address(nocache=True)
        ch_core.hookenv.log("Rejoin instance: {}.".format(address))
        _script = (
            "shell.connect('{user}:{pw}@{caddr}')\n"
            "cluster = dba.get_cluster('{name}')\n"
            "cluster.remove_instance('{user}@{addr}', {{'force': {force}}})"
            .format(
                user=self.cluster_user, pw=self.cluster_password,
                caddr=_primary or self.cluster_address,
                name=self.cluster_name, addr=address, force=force))
        try:
            output = self.run_mysqlsh_script(_script).decode("UTF-8")
            ch_core.hookenv.log(
                "Remove instance {} successful: "
                "{}".format(address, output),
                level="DEBUG")
            return output
        except subprocess.CalledProcessError as e:
            ch_core.hookenv.log(
                "Failed removing instance {}: {}"
                .format(address, e.stderr.decode("UTF-8")),
                "ERROR")
            # Reraise for action handling
            raise e

    def cluster_rescan(self):
        """Rescan the cluster

        Execute the cluster.rescan() to cleanup metadata.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :side effect: Calls self.run_mysqlsh_script
        :returns: This function is called for its side effect
        :rtype: None
        """
        _primary = self.get_cluster_primary_address(nocache=True)
        ch_core.hookenv.log("Rescanning the cluster.")
        _script = (
            "shell.connect('{user}:{pw}@{caddr}')\n"
            "cluster = dba.get_cluster('{name}')\n"
            "cluster.rescan()"
            .format(
                user=self.cluster_user, pw=self.cluster_password,
                caddr=_primary or self.cluster_address,
                name=self.cluster_name))
        try:
            output = self.run_mysqlsh_script(_script).decode("UTF-8")
            ch_core.hookenv.log(
                "Cluster rescan successful",
                level="DEBUG")
            return output
        except subprocess.CalledProcessError as e:
            ch_core.hookenv.log(
                "Failed rescanning the cluster.",
                "ERROR")
            # Reraise for action handling
            raise e

    def configure_and_add_instance(self, address):
        """Configure and add an instance to the cluster.

        If an instance was not able to be joined to the cluster this method
        will make sure it is configured and add it to the cluster.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :side effect: Calls self.create_user, self.configure_instance and
                      self.add_instance_to_cluster.
        :returns: This function is called for its side effects
        :rtype: None
        """
        ch_core.hookenv.log(
            "Configuring and adding instance to the cluster: {}."
            .format(address))
        cluster = reactive.endpoint_from_flag("cluster.available")
        if not cluster:
            raise Exception(
                "Cluster relation is not available in order to "
                "create cluster user for {}.".format(address))
        # Make sure we have the user in the DB
        for unit in cluster.all_joined_units:
            if not self.create_cluster_user(
                    unit.received['cluster-address'],
                    unit.received['cluster-user'],
                    unit.received['cluster-password']):
                raise Exception(
                    "Not all cluster users created.")
        self.configure_instance(address)
        self.add_instance_to_cluster(address)

    def get_cluster_status(self, nocache=False):
        """Get cluster status

        Return cluster.status() as a dictionary. If cached data exists and is
        not explicity avoided with the nocache parameter, avoid the expensive
        DB query.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :param nocache: Do not return cached data
        :type nocache: Boolean
        :side effect: Calls self.check_mysql_connection
        :returns: Dictionary cluster status output
        :rtype: Union[None, dict]
        """
        # Speed up when we are not yet clustered
        if not reactive.is_flag_set(
                "leadership.set.cluster-instance-clustered-{}"
                .format(self.cluster_address)):
            ch_core.hookenv.log(
                "This instance is not yet clustered: cannot determine the "
                "cluster status.", "WARNING")
            return

        # Try the cached version first
        if self._cached_cluster_status and not nocache:
            return self._cached_cluster_status

        ch_core.hookenv.log("Checking cluster status.", "DEBUG")
        # Cluster must be up and healthy
        try:
            self.wait_until_cluster_available()
        except subprocess.CalledProcessError as e:
            ch_core.hookenv.log(
                "Cluster is unavailable: {}"
                .format(e.stderr.decode("UTF-8")), "ERROR")
            return

        _script = (
            "shell.connect('{}:{}@{}')\n"
            "cluster = dba.get_cluster('{}')\n"
            "print(cluster.status())"
            .format(self.cluster_user, self.cluster_password,
                    self.cluster_address, self.cluster_name))
        try:
            output = self.run_mysqlsh_script(_script)
        except subprocess.CalledProcessError as e:
            ch_core.hookenv.log(
                "Failed checking cluster status: {}"
                .format(e.stderr.decode("UTF-8")), "ERROR")
            return
        self._cached_cluster_status = json.loads(output.decode("UTF-8"))
        return self._cached_cluster_status

    def get_cluster_primary_address(self, nocache=False):
        """Get cluster RW primary address.

        Return cluster.status()['groupInformationSourceMember'] which is the
        primary R/W node in the cluster.  This node is safe to use for writes
        to the cluster.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :param nocache: Do not return cached data
        :type nocache: Boolean
        :side effect: Calls self.get_cluster_status
        :returns: String IP address
        :rtype: Union[None, str]
        """
        if self._cached_cluster_status and not nocache:
            _status = self._cached_cluster_status
        else:
            _status = self.get_cluster_status(nocache=nocache)
        if not _status:
            return
        # Return addresss without port number
        if ":" in _status['groupInformationSourceMember']:
            return _status['groupInformationSourceMember'][:-5]
        return _status['groupInformationSourceMember']

    def get_cluster_status_summary(self, nocache=False):
        """Get cluster status summary

        Return cluster.status()["defaultReplicaSet"]["status"]. This will be
        "OK" if the cluster is healhty. If cached data exists and is not
        explicity avoided with the nocache parameter, avoid the call to
        self.get_cluster_status.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :param nocache: Do not return cached data
        :type nocache: Boolean
        :side effect: Calls self.get_cluster_status
        :returns: String status. i.e. "OK"
        :rtype: Union[None, str]
        """
        if self._cached_cluster_status and not nocache:
            _status = self._cached_cluster_status
        else:
            _status = self.get_cluster_status(nocache=nocache)
        if not _status:
            return
        return _status["defaultReplicaSet"]["status"]

    def get_cluster_status_text(self, nocache=False):
        """Get cluster status text

        Return cluster.status()["defaultReplicaSet"]["statusText"]. This is
        useful information if the cluster is not healthy. If cached data
        exists and is not explicity avoided with the nocache parameter, avoid
        the call to self.get_cluster_status.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :param nocache: Do not return cached data
        :type nocache: Boolean
        :side effect: Calls self.get_cluster_status
        :returns: String status text. i.e. "Cluster is ONLINE"...
        :rtype: Union[None, str]
        """
        if self._cached_cluster_status and not nocache:
            _status = self._cached_cluster_status
        else:
            _status = self.get_cluster_status(nocache=nocache)
        if not _status:
            return
        return _status["defaultReplicaSet"]["statusText"]

    def get_cluster_instance_mode(self, nocache=False):
        """Get cluster status mode

        Return cluster.status()["defaultReplicaSet"]["topology"]. This will be
        "R/W" or "R/O" depending on the mode of this instance in the cluster.
        If cached data exists and is not explicity avoided with the nocache
        parameter, avoid the call to self.get_cluster_status.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :param nocache: Do not return cached data
        :type nocache: Boolean
        :side effect: Calls self.get_cluster_status
        :returns: String mode. i.e. "R/W" or "R/O"
        :rtype: Union[None, str]
        """
        if self._cached_cluster_status and not nocache:
            _status = self._cached_cluster_status
        else:
            _status = self.get_cluster_status(nocache=nocache)
        if not _status:
            return
        return (_status["defaultReplicaSet"]["topology"]
                ["{}:{}".format(self.cluster_address, self.cluster_port)]
                ["mode"])

    # TODO: Generalize and move to mysql charmhelpers
    def get_allowed_units(self, database, username, relation_id,
                          db_helper=None, prefix=None):
        """Get Allowed Units.

        Call MySQL8Helper.get_allowed_units and return space delimited list of
        allowed unit names.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :param database: Database name
        :type database: str
        :param username: Username
        :type username: str
        :param relation_id: Relation ID
        :type relation_id: str
        :param db_helper: DB Helper instnace
        :type db_helper: MySQLDB8Helper instance
        :param prefix: Prefix for db request
        :type prefix: str
        :returns: Space delimited list of unit names
        :rtype: str
        """
        if not db_helper:
            db_helper = self.get_db_helper()
        allowed_units = db_helper.get_allowed_units(
            database, username, relation_id=relation_id, prefix=prefix)
        allowed_units = sorted(
            allowed_units, key=lambda a: int(a.split('/')[-1]))
        allowed_units = ' '.join(allowed_units)
        return allowed_units

    def create_databases_and_users(self, interface):
        """Create databases and users.

        Take an Endpoint interface and create databases and users based on the
        requests on the relation.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :param interface: Interface Object (shared-db or db-router)
        :type interface: reactive.relations.Endpoint object
        :side effect: interface.set_db_connection_info is executed
        :returns: True if successful
        :rtype: Bool
        """
        if interface is None:
            ch_core.hookenv.log(
                "create_databases_and_users received a NoneType interface. "
                "We may be in a departing hook. Skipping "
                "create_databases_and_users", "WARNING")
            return False
        completed = []
        db_host = ch_net_ip.get_relation_ip(interface.endpoint_name)
        db_helper = self.get_db_helper()
        rw_helper = self.get_cluster_rw_db_helper()
        for unit in interface.all_joined_units:
            db_data = mysql.get_db_data(
                dict(unit.received),
                unprefixed=self._unprefixed)
            mysqlrouterset = {'username', 'hostname'}
            singleset = {'database', 'username', 'hostname'}

            for prefix in db_data:
                if singleset.issubset(db_data[prefix]):
                    database = db_data[prefix]['database']
                    hostname = db_data[prefix]['hostname']
                    username = db_data[prefix]['username']

                    password = self.configure_db_for_hosts(
                        hostname, database, username,
                        rw_helper=rw_helper)
                    completed.append(password)

                    allowed_units = self.get_allowed_units(
                        database, username,
                        unit.relation.relation_id,
                        db_helper=db_helper,
                        prefix=prefix)

                    if prefix in self._unprefixed:
                        prefix = None

                elif mysqlrouterset.issubset(db_data[prefix]):
                    hostname = db_data[prefix]['hostname']
                    username = db_data[prefix]['username']

                    password = self.configure_db_router(
                        hostname,
                        username,
                        rw_helper=rw_helper)
                    completed.append(password)
                    allowed_units = " ".join(
                        [x.unit_name for x in unit.relation.joined_units])

                if not self.ssl_ca:
                    # Reset ssl_ca in case we previously had it set
                    ch_core.hookenv.log(
                        "Proactively resetting ssl_ca", "DEBUG")
                    interface.relations[
                        unit.relation.relation_id].to_publish_raw[
                            "ssl_ca"] = None

                # Only set relation data if db/user create was successful
                if password:
                    interface.set_db_connection_info(
                        unit.relation.relation_id,
                        db_host,
                        password,
                        allowed_units=allowed_units,
                        prefix=prefix,
                        wait_timeout=self.options.wait_timeout,
                        ssl_ca=self.ssl_ca)

        # Validate that all attempts succeeded.
        # i.e. We were not attempting writes during a topology change,
        # we are not attempting to write to a read only node.
        if all(completed):
            return True
        return False

    # TODO: Generalize and move to mysql charmhelpers
    def configure_db_for_hosts(self, hosts, database, username,
                               rw_helper=None):
        """Configure database for user at host(s).

        Create and configure database and user with full access permissions
        from host(s).

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :param hosts: Hosts may be a json-encoded list of hosts or a single
                      hostname.
        :type hosts: Union[str, Json list]
        :param database: Database name
        :type database: str
        :param username: Username
        :type username: str
        :param rw_helper: Instance of MySQL8Helper
        :type rw_helper: charmhelpers.contrib.database.mysql.MySQL8Helper
        :side effect: Calls MySQL8Helper.configure_db
        :returns: Password for the DB user
        :rtype: str
        """
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
        if not rw_helper:
            rw_helper = self.get_cluster_rw_db_helper()
        if not rw_helper:
            ch_core.hookenv.log(
                "No connection to the cluster primary RW node "
                "skipping DB creation.",
                "WARNING")
            return

        for host in hosts:
            try:
                password = rw_helper.configure_db(host, database, username)
            except mysql.MySQLdb._exceptions.OperationalError as e:
                if e.args[0] == self._read_only_error:
                    password = None
                    ch_core.hookenv.log(
                        "Attempted to write to the RO node: {} in "
                        "configure_db_for_hosts. Skipping."
                        .format(rw_helper.connection.get_host_info()),
                        "WARNING")
                else:
                    raise

        return password

    def configure_db_router(self, hosts, username, rw_helper=None):
        """Configure database for MySQL Router user at host(s).

        Create and configure MySQL Router user with mysql router specific
        permissions from host(s).

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :param hosts: Hosts may be a json-encoded list of hosts or a single
                      hostname.
        :type hosts: Union[str, Json list]
        :param username: Username
        :type username: str
        :param rw_helper: Instance of MySQL8Helper
        :type rw_helper: charmhelpers.contrib.database.mysql.MySQL8Helper
        :side effect: Calls MySQL8Helper.configure_router
        :returns: Password for the DB user
        :rtype: str
        """
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

        if not rw_helper:
            rw_helper = self.get_cluster_rw_db_helper()
        if not rw_helper:
            ch_core.hookenv.log(
                "No connection to the cluster primary RW node "
                "skipping DB creation.",
                "WARNING")
            return

        for host in hosts:
            try:
                password = rw_helper.configure_router(host, username)
            except mysql.MySQLdb._exceptions.OperationalError as e:
                if e.args[0] == self._read_only_error:
                    password = None
                    ch_core.hookenv.log(
                        "Attempted to write to the RO node: {} in "
                        "configure_db_router. Skipping."
                        .format(rw_helper.connection.get_host_info()),
                        "WARNING")
                else:
                    raise

        return password

    def states_to_check(self, required_relations=None):
        """Custom states to check function.

        Construct a custom set of connected and available states for each
        of the relations passed, along with error messages and new status
        conditions.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :param required_relations: List of relations which overrides
                                   self.relations
        :type required_relations: list of strings
        :returns: {relation: [(state, err_status, err_msg), (...),]}
        :rtype: dict
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

    def _assess_status(self):
        """Completely override _assess_status

        Custom assess status check that validates connectivity to this unit's
        MySQL instance, checks the health of the cluster and reports this
        unit's cluster mode. i.e. R/W or R/O.

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :side effect: Calls status_set
        :returns: This function is called for its side effect
        :rtype: None
        """
        # Set version
        ch_core.hookenv.application_version_set(self.application_version)
        # Start with default checks
        for f in [self.check_if_paused,
                  self.check_interfaces,
                  self.check_mandatory_config,
                  self.check_services_running]:
            state, message = f()
            if state is not None:
                ch_core.hookenv.status_set(state, message)
                return

        # We should not get here until there is a connection to the
        # cluster available.
        if not self.check_mysql_connection():
            ch_core.hookenv.status_set(
                "blocked", "MySQL is down on this instance")
            return

        # Check the state of the cluster. nocache=True will get live info
        _cluster_status = self.get_cluster_status_summary(nocache=True)
        if not _cluster_status or "OK" not in _cluster_status:
            ch_core.hookenv.status_set(
                "blocked",
                "MySQL InnoDB Cluster not healthy: {}"
                .format(self.get_cluster_status_text()))
            return

        # All is good. Report this instance's mode to workgroup status
        ch_core.hookenv.status_set(
            "active",
            "Unit is ready: Mode: {}"
            .format(self.get_cluster_instance_mode()))

    def check_mysql_connection(
            self, username=None, password=None, address=None):
        """Check if an instance of MySQL is accessible.

        Attempt a connection to the given instance of mysql to determine if it
        is running and accessible.

        :param username: Username
        :type username: str
        :param password: Password to use for connection test.
        :type password: str
        :param address: Address of the MySQL instance to connect to
        :type address: str
        :side effect: Uses get_db_helper to execute a connection to the DB.
        :returns: True if connection succeeds or False if not
        :rtype: boolean
        """
        address = address or "localhost"
        password = password or self.mysql_password
        username = username or "root"

        m_helper = self.get_db_helper()
        try:
            m_helper.connect(user=username, password=password, host=address)
            return True
        except mysql.MySQLdb._exceptions.OperationalError:
            ch_core.hookenv.log("Could not connect to {}@{}"
                                .format(username, address), "DEBUG")
            return False

    @tenacity.retry(wait=tenacity.wait_fixed(10),
                    reraise=True,
                    stop=tenacity.stop_after_attempt(5))
    def wait_until_connectable(
            self, username=None, password=None, address=None):
        """Wait until MySQL instance is accessible.

        Attempt a connection to the given instance of mysql, retry on failure
        using tenacity until successful or number of retries reached.

        This is useful for waiting when the MySQL instance may be restarting.

        Warning: Use sparingly. This function asserts connectivity and raises
        CannotConnectToMySQL if it is unsuccessful on all retries.

        :param username: Username
        :type username: str
        :param password: Password to use for connection test.
        :type password: str
        :param address: Address of the MySQL instance to connect to
        :type address: str
        :side effect: Calls self.check_mysql_connection
        :raises CannotConnectToMySQL: Raises CannotConnectToMySQL if number of
                                      retires exceeded.
        :returns: This function is called for its side effect
        :rtype: None
        """
        if not self.check_mysql_connection(
                username=username, password=password, address=address):
            raise CannotConnectToMySQL("Unable to connect to MySQL")

    @tenacity.retry(wait=tenacity.wait_fixed(6),
                    reraise=True,
                    stop=tenacity.stop_after_attempt(5))
    def wait_until_cluster_available(self):
        """Wait until MySQL InnoDB Cluster is available.

        Attempt a running getCluster until the cluster is healthy
        using tenacity until successful or number of retries reached.

        This is useful for waiting when the MySQL cluster may be restarting
        instances and we want to wait until the cluster is back to healthy.

        Warning: Use sparingly. This function asserts connectivity and raises
        CannotConnectToMySQL if it is unsuccessful on all retries.

        :side effect: Calls self.run_mysqlsh_script
        :raises subprocess.CalledProcessError: Raises CalledProcessError if the
                                               number of retires is exceeded.
        :returns: This function is called for its side effect
        :rtype: None
        """
        _script = (
            "shell.connect('{}:{}@{}')\n"
            "cluster = dba.get_cluster('{}')"
            .format(
                self.cluster_user, self.cluster_password, self.cluster_address,
                self.cluster_name))
        self.run_mysqlsh_script(_script)

    def run_mysqlsh_script(self, script):
        """Execute a MySQL shell script

        :param script: Mysqlsh script
        :type script: str
        :side effect: Calls subprocess.check_output
        :raises subprocess.CalledProcessError: Raises CalledProcessError if the
                                               script gets a non-zero return
                                               code.
        :returns: subprocess output
        :rtype: UTF-8 byte string
        """
        if not os.path.exists(self.mysqlsh_common_dir):
            # Pre-execute mysqlsh to create self.mysqlsh_common_dir
            # If we don't do this the real execution will fail with an
            # ambiguous error message. This will only ever execute once.
            cmd = [self.mysqlsh_bin, "--help"]
            subprocess.check_call(cmd, stderr=subprocess.PIPE)

        # Use the self.mysqlsh_common_dir dir for the confined
        # mysql-shell snap.
        with tempfile.NamedTemporaryFile(
                mode="w", suffix=".py",
                dir=self.mysqlsh_common_dir) as _file:
            _file.write(script)
            _file.flush()

            # Specify python as this is not the default in the deb version
            # of the mysql-shell snap
            cmd = [
                self.mysqlsh_bin, "--no-wizard", "--python", "-f", _file.name]
            return subprocess.check_output(cmd, stderr=subprocess.PIPE)

    def write_root_my_cnf(self):
        """Write root my.cnf

        :side effect: calls render()
        :returns: None
        :rtype: None
        """
        my_cnf_template = "root-my.cnf"
        root_my_cnf = "/root/.my.cnf"
        context = {"mysql_passwd": self.mysql_password}
        ch_core.templating.render(
            my_cnf_template, root_my_cnf, context, perms=0o600)

    def mysqldump(self, backup_dir, databases=None):
        """Execute a MySQL dump

        :param backup_dir: Path to the backup directory
        :type backup_dir: str
        :param databases: Comma delimited database names
        :type database: str
        :side effect: Calls subprocess.check_call
        :raises subprocess.CalledProcessError: If the mysqldump fails
        :returns: Path to the mysqldump file
        :rtype: str
        """
        # In order to enable passwordless use of mysqldump
        # write out my.cnf for user root
        self.write_root_my_cnf()
        # Enable use of my.cnf by setting HOME env variable
        os.environ["HOME"] = "/root"
        _user = "root"
        _delimiter = ","
        if not os.path.exists(backup_dir):
            ch_core.host.mkdir(
                backup_dir, owner="mysql", group="mysql", perms=0o750)

        bucmd = ["/usr/bin/mysqldump", "-u", _user,
                 "--triggers", "--routines", "--events",
                 "--ignore-table=mysql.event"]
        if databases is not None:
            _filename = os.path.join(
                backup_dir,
                "mysqldump-{}-{}".format(
                    "-".join(databases.split(_delimiter)),
                    datetime.datetime.now().strftime("%Y%m%d%H%M")))
            bucmd.extend(["--result-file", _filename, "--databases"])
            bucmd.extend(databases.split(_delimiter))
        else:
            _filename = os.path.join(
                backup_dir,
                "mysqldump-all-databases-{}".format(
                    datetime.datetime.now().strftime("%Y%m%d%H%M")))
            bucmd.extend(["--result-file", _filename, "--all-databases"])
        subprocess.check_call(bucmd)
        gzcmd = ["/usr/bin/gzip", _filename]
        subprocess.check_call(gzcmd)
        return "{}.gz".format(_filename)

    def restore_mysqldump(self, dump_file):
        """Restore a MySQL dump file

        :param dump_file: Path to mysqldump file to restored.
        :type dump_file: str
        :side effect: Calls subprocess.check_call
        :raises subprocess.CalledProcessError: If the mysqldump fails
        :returns: This function is called for its side effect
        :rtype: None
        """
        # In order to enable passwordless use of mysql
        # write out my.cnf for user root
        self.write_root_my_cnf()
        # Enable use of my.cnf by setting HOME env variable
        os.environ["HOME"] = "/root"
        # Gunzip if necessary
        if ".gz" in dump_file:
            gunzip = ["gunzip", dump_file]
            subprocess.check_call(gunzip)
            dump_file = dump_file[:-3]
        _user = "root"
        restore_cmd = ["mysql", "-u", _user]
        restore = subprocess.Popen(restore_cmd, stdin=subprocess.PIPE)
        with open(dump_file, "rb") as _sql:
            restore.communicate(input=_sql.read())
        restore.wait()

    @property
    def cluster_peer_addresses(self):
        """Cluster peer addresses

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :returns: Cluster peer addresses
        :rtype: list
        """
        ep = reactive.endpoint_from_flag("cluster.available")
        return [unit.received["cluster-address"]
                for unit in ep.all_joined_units
                if unit.received["cluster-address"]]

    @property
    def mysql_server_bindings(self):
        """MySQL Server Bindings

        :param self: Self
        :type self: MySQLInnoDBClusterCharm instance
        :returns: Bindings where MySQL is listening
        :rtype: list
        """
        return ["db-router", "cluster", "shared-db"]

    def configure_tls(self, certificates_interface=None):
        """Configure TLS certificates and keys

        :param certificates_interface: certificates relation endpoint
        :type certificates_interface: Union[None, Endpoint]
        """
        # We may have a relation but not been called with
        # certificates_interface set
        if not certificates_interface:
            certificates_interface = (
                reactive.endpoint_from_flag('certificates.available'))
        ch_core.hookenv.log("Configuring TLS with certificates interface={}"
                            .format(certificates_interface), "DEBUG")
        path = os.path.join('/etc/mysql/tls/', self.name)
        if (self.config_defined_ssl_cert and
                self.config_defined_ssl_key):
            ch_core.hookenv.log("Configuring config based SSL", "DEBUG")
            if self.config_defined_ssl_ca:
                ch_core.hookenv.log("Configurationg config based SSL", "DEBUG")
                self.configure_ca(self.config_defined_ssl_ca.decode("UTF-8"))
            self.configure_cert(
                path,
                self.config_defined_ssl_cert.decode("UTF-8"),
                self.config_defined_ssl_key.decode("UTF-8"),
                cn=self.db_router_address)
            reactive.set_flag('tls.enabled')
            return
        elif not certificates_interface:
            reactive.clear_flag('tls.enabled')
            return

        # this takes care of writing out the CA certificate
        tls_objects = super().configure_tls(
            certificates_interface=certificates_interface)
        with chos_utils.is_data_changed(
                'configure_tls.tls_objects', tls_objects) as changed:
            if tls_objects:
                for tls_object in tls_objects:
                    reactive.set_flag('tls.requested')
                    self.configure_cert(
                        path,
                        tls_object['cert'],
                        tls_object['key'],
                        cn=tls_object['cn'])
                cert_utils.create_ip_cert_links(
                    path, bindings=self.mysql_server_bindings)
                if changed:
                    reactive.clear_flag('tls.requested')
                    reactive.set_flag('tls.enabled')
                    if ch_core.hookenv.is_leader():
                        self.render_all_configs()
                    else:
                        # Mysql InnodB Cluster uses coordinator for rolling
                        # restarts. Request a restart.
                        coordinator.acquire('config-changed-restart')

            else:
                reactive.clear_flag('tls.enabled')
