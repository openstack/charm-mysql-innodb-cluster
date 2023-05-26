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
import ipaddress
import json
import os
import re
import subprocess
import tenacity
import tempfile
import uuid
from typing import Literal

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

import charm.openstack.exceptions as exceptions


MYSQLD_CNF = "/etc/mysql/mysql.conf.d/mysqld.cnf"
CLUSTER_INSTANCE_CONFIGURED = "cluster-instance-configured-{}"
CLUSTER_INSTANCE_CLUSTERED = "cluster-instance-clustered-{}"


def make_cluster_instance_configured_key(address):
    return CLUSTER_INSTANCE_CONFIGURED.format(
        address.replace(".", "-"))


def make_cluster_instance_clustered_key(address):
    return CLUSTER_INSTANCE_CLUSTERED.format(
        address.replace(".", "-"))


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
    """Determine the value for innodb_change_buffering.

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
    """Determine the value for innodb_buffer_pool_size.

    Call the MySQLConfigHelper innodb_buffer_pool_size helper to get the value
    for innodb_buffer_pool_size.

    :param cls: Class
    :type cls: ConfigurationAdapter class
    :returns: Numeric innodb_buffer_pool_size value
    :rtype: int
    """
    return mysql.get_mysql_config_helper().get_innodb_buffer_pool_size()


@charms_openstack.adapters.config_property
def group_replication_message_cache_size_adapter(cls):
    """Determine the value for group_replication_message_cache_size.

    Call the MySQLConfigHelper get_group_replication_message_cache_size
    helper to get the value for group_replication_message_cache_size.

    :param cls: Class
    :type cls: ConfigurationAdapter class
    :returns: Numeric group_replication_message_cache_size value
    :rtype: int
    """
    return mysql.get_mysql_config_helper()\
        .get_group_replication_message_cache_size()


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


class MySQLPrometheusExporterMixin:
    """Mixin for the Prometheus exporter service.

    The mixin should only inheritance by MySQLInnoDBClusterCharm.
    """

    @property
    def prometheus_exporter_user(self):
        """Return the prometheus exporter username.

        :returns: Exporter username
        :rtype: str
        """
        return "prom_exporter"

    @property
    def prometheus_exporter_password(self):
        """Return or set password for the prometheus exporter user.

        :returns: Exporter password
        :rtype: str
        """
        return self._get_password("prom_exporter_password")

    @property
    def prometheus_exporter_port(self):
        """Return this unit's prometheus exporter port.

        Using the class method determine this unit's prom_exporter address.

        :returns: Port
        :rtype: str
        """
        return "9104"


class MySQLInnoDBClusterCharm(
    MySQLPrometheusExporterMixin,
    charms_openstack.charm.OpenStackCharm,
):
    """Charm class for the MySQLInnoDBCluster charm."""
    name = "mysql-innodb-cluster"
    release = "train"
    packages = ["mysql-router", "mysql-server-8.0", "python3-dnspython"]
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
    _local_socket_connection_error = 2002
    _before_commit_error = 3100

    @property
    def mysqlsh_bin(self):
        """Determine binary path for MySQL Shell.

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

        :returns: Path to common dir
        :rtype: str
        """
        return "/root/snap/mysql-shell/common"

    @property
    def mysql_password(self):
        """Determine or set primary MySQL password.

        :returns: MySQL password
        :rtype: str
        """
        return self._get_password("mysql.passwd")

    @property
    def cluster_name(self):
        """Determine the MySQL InnoDB Cluster name.

        :returns: Cluster name
        :rtype: str
        """
        return self.options.cluster_name

    @property
    def cluster_password(self):
        """Determine or set password for the cluster user.

        :returns: Cluster password
        :rtype: str
        """
        return self._get_password("cluster-password")

    @property
    def cluster_address(self):
        """Determine this unit's cluster address.

        Using the class method determine this unit's cluster address.

        :returns: Address
        :rtype: str
        """
        return self.options.cluster_address

    @property
    def cluster_port(self):
        """Determine this unit's cluster port.

        Using the class method determine this unit's cluster address.

        :returns: Port
        :rtype: str
        """
        return "3306"

    @property
    def cluster_user(self):
        """Determine the cluster username.

        :returns: Cluster username
        :rtype: str
        """
        return "clusteruser"

    @property
    def cluster_relation_endpoint(self):
        """Determine the cluster username.

        :returns: Cluster username
        :rtype: str
        """
        return reactive.endpoint_from_flag("cluster.available")

    @property
    def shared_db_address(self):
        """Determine this unit's Shared-DB address.

        Using the class method determine this unit's address for the Shared-DB
        relation.

        :returns: Address
        :rtype: str
        """
        return self.options.shared_db_address

    @property
    def db_router_address(self):
        """Determine this unit's Shared-DB address.

        Using the class method determine this unit's address for the DB-Router
        relation.

        :returns: Address
        :rtype: str
        """
        return self.options.db_router_address

    @property
    def ssl_ca(self):
        """Return the SSL Certificate Authority

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

        :returns: Instance of MySQLDB8Helper class
        :rtype: Union[None, MySQLDB8Helper]
        """
        _primary = self.get_cluster_primary_address(nocache=True)
        if not _primary:
            ch_core.hookenv.log(
                "Cannot determine the cluster primary RW node for writes.",
                "WARNING")
            return None
        _helper = self.get_db_helper()
        _helper.connect(
            user=self.cluster_user,
            password=self.cluster_password,
            host=self.get_cluster_primary_address(nocache=True))
        return _helper

    @staticmethod
    def _grant_user_privileges(
        m_helper,
        address,
        user,
        privilege: Literal["all", "read_only", "prom_exporter"],
    ):
        """Grant privileges for cluster user.

        :param m_helper: connected RW instance of the MySQLDB8Helper class
        :type m_helper: Instance of MySQLDB8Helper class
        :param address: address for which privileges will be granted
        :type address: str
        :param user: Cluster user's username
        :type user: str
        :param privilege: User permission
        :type privilege:
            Literal["all", "read_only", "prom_exporter"]
        :side effect: Executes SQL to revoke and grand privileges for user
        """
        sql_grant = "GRANT {permissions} ON *.* TO '{user}'@'{host}'"
        sql_revoke = "REVOKE ALL PRIVILEGES ON *.* FROM '{user}'@'{host}'"
        if privilege == "read_only":
            permissions = "SELECT, SHOW VIEW"
        elif privilege == "prom_exporter":
            permissions = "PROCESS, REPLICATION CLIENT"
        else:
            permissions = "ALL PRIVILEGES"
            # NOTE (rgildein): The WITH GRANT OPTION clause gives the user the
            # ability to give to other users any privileges the user has at the
            # specified privilege level.
            sql_grant += " WITH GRANT OPTION"

        ch_core.hookenv.log(
            "Revoke all privileges for use '{user}'@'{host}'".format(
                user=user, host=address
            ),
            ch_core.hookenv.DEBUG)
        m_helper.execute(sql_revoke.format(user=user, host=address))

        ch_core.hookenv.log(
            "Grant {permissions} for use '{user}'@'{host}'".format(
                permissions=permissions,
                user=user,
                host=address
            ),
            ch_core.hookenv.DEBUG)
        m_helper.execute(sql_grant.format(
            permissions=permissions, user=user, host=address
        ))

        m_helper.execute("FLUSH PRIVILEGES")

    @tenacity.retry(stop=tenacity.stop_after_attempt(6),
                    wait=tenacity.wait_fixed(10),
                    retry=tenacity.retry_if_result(lambda x: x is False))
    def create_user(
        self,
        address,
        user,
        password,
        user_privilege,
    ):
        """Create user and grant permissions in the MySQL DB.

        This user will be used by the leader for instance configuration and
        initial cluster creation.

        The grants are specific to cluster creation and management as
        documented upstream.

        NOTE: LP#2015256 means that if this unit is supposed to be part of a
        cluster but can't acquire a cluster rw db_helper object hen it should
        fail by returning False.  This is done by checking for the configured'
        flag, and if True, also checking for the 'clustered' flag in the
        leadership settings.  If the unit isn't clustered, but is configured,
        then the function gives up.

        NOTE: LP#2018383 means that the function may return False in the
        prometheus-relation-joined hook if the cluster is recovering from
        switching to TLS and recovering Group Replication.  The function
        detects this error (3100), and returns False.  The tenacity retry on
        the method retries the function after 10 seconds, 6 times, allowing for
        1 minute for the Group Replication to recover during the hook
        execution. Otherwise, the function returns False to allow the caller to
        decide what to do on the failure.

        The function returns None if the unit is not configured in cluster or
        the helper can't connect to the local socket, neither of which are
        recoverable in this function.

        :param address: User's address
        :type address: str
        :param exporter_user: User's username
        :type user: str
        :param password: User's password
        :type password: str
        :param privilege: User permission
        :type privilege: Literal[all, read_only, prom_exporter]
        :side effect: Executes SQL to create DB user
        :returns: True if successful, False|None if there are failures
        :rtype: Optional(Bool)
        """
        SQL_CLUSTER_USER_CREATE = (
            "CREATE USER '{user}'@'{host}' "
            "IDENTIFIED BY '{password}'")

        addresses = [address]
        if address in self.cluster_address:
            addresses.append("localhost")

        # If this is scale out and the cluster already exists, use the cluster
        # RW node for writes.
        m_helper = self.get_cluster_rw_db_helper()
        if not m_helper:
            # NOTE: Bug LP#2015256 - verify that the unit, if configured into
            # the cluster, is actually part of the cluster
            configured_flag = (
                "leadership.set.{}"
                .format(make_cluster_instance_configured_key(
                    self.cluster_address)))
            clustered_flag = (
                "leadership.set.{}"
                .format(make_cluster_instance_clustered_key(
                    self.cluster_address)))
            if (reactive.is_flag_set(configured_flag) and
                    not reactive.is_flag_set(clustered_flag)):
                ch_core.hookenv.log(
                    "Attempting to create a user (function create_user()) "
                    "when this instance is configured for the cluster but "
                    "not yet in the cluster. Skipping.",
                    "INFO")
                return None

            # Otherwise, this unit is not configured for the cluster
            m_helper = self.get_db_helper()
            try:
                m_helper.connect(password=self.mysql_password)
            except mysql.MySQLdb._exceptions.OperationalError as e:
                if e.args[0] == self._local_socket_connection_error:
                    ch_core.hookenv.log(
                        "Couldn't connect to local socket when trying to "
                        "create the user: '{}'.".format(user),
                        "WARNING")
                    return None
                raise

        for address in addresses:
            try:
                m_helper.execute(SQL_CLUSTER_USER_CREATE.format(
                    user=user,
                    host=address,
                    password=password)
                )
                self._grant_user_privileges(
                    m_helper, address, user, user_privilege,
                )
            except mysql.MySQLdb._exceptions.OperationalError as e:
                if e.args[0] == self._read_only_error:
                    ch_core.hookenv.log(
                        "Attempted to write to the RO node: {} in "
                        "create_user. Skipping."
                        .format(m_helper.connection.get_host_info()),
                        "WARNING")
                    return False
                if e.args[0] == self._user_create_failed:
                    ch_core.hookenv.log(
                        "User {} exists.".format(user), "WARNING")
                    # NOTE (rgildein): This is necessary to ensure that the
                    # existing user has the correct privileges.
                    self._grant_user_privileges(
                        m_helper, address, user, user_privilege,
                    )
                    continue
                if e.args[0] == self._before_commit_error:
                    ch_core.hookenv.log(
                        "Couldn't commit due to error {}; most likely the "
                        "cluster's group replication recovery is in process "
                        .format(self._before_commit_error),
                        "WARNING")
                    return False
                raise
        return True

    def configure_instance(self, address):
        """Configure MySQL instance for clustering.

        :param address: Address of the MySQL instance to be configured
        :type address: str
        :side effect: Calls self.run_mysqlsh_script
        :returns: This function is called for its side effect
        :rtype: None
        """
        if reactive.is_flag_set(
                "leadership.set.{}"
                .format(make_cluster_instance_configured_key(address))):
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
        leadership.leader_set({
            make_cluster_instance_configured_key(address): True})

    def get_cluster_addresses(self):
        """Return a sorted list of addresses covering all units.

        :returns: List of addresses
        :rtype: List
        """
        ips = self.cluster_peer_addresses
        ips.append(self.cluster_address)
        ips.append(ch_net_ip.resolve_network_cidr(self.cluster_address))
        return sorted(ips)

    def generate_ip_allowlist_str(self):
        """Generate an ip allow list to permit all units to access each other.

        Generate an ip allow list to permit all units to access each other
        and to allow localhost connections.

        :returns: Value for ip allow list for this cluster
        :rtype: str
        """
        return "127.0.0.1,::1,{}".format(
            ",".join(self.get_cluster_addresses()))

    def reached_quorum(self):
        """Check if all peer units have joined.

        Compare the number of units reported in goal state with the number of
        units that have advertised their cluster address on the peer relation.

        :returns: Whether all peer units have joined
        :rtype: Boolean
        """
        cluster = reactive.endpoint_from_flag("cluster.available")
        peer_addresses = [u.received['cluster-address']
                          for u in cluster.all_joined_units
                          if u.received['cluster-address']]
        ch_core.hookenv.log(
            "Found peers: {}".format(",".join(peer_addresses)),
            "DEBUG")
        expected_unit_count = len(list(ch_core.hookenv.expected_peer_units()))
        ch_core.hookenv.log(
            "Expect {} peers".format(expected_unit_count),
            "DEBUG")
        return len(peer_addresses) >= expected_unit_count

    def create_cluster(self):
        """Create the MySQL InnoDB cluster.

        Creates the MySQL InnoDB cluster using self.cluster_name.

        :side effect: Calls self.run_mysqlsh_script
        :returns: This function is called for its side effect
        :rtype: None
        """
        if reactive.is_flag_set("leadership.set.cluster-created"):
            ch_core.hookenv.log("Cluster: {}, already created"
                                .format(self.options.cluster_name), "WARNING")
            return

        if not reactive.is_flag_set(
                "leadership.set.{}"
                .format(make_cluster_instance_configured_key(
                    self.cluster_address))):
            ch_core.hookenv.log("This instance is not yet configured for "
                                "clustering, delaying cluster creation.",
                                "WARNING")
            return

        _script = (
            "shell.connect('{}:{}@{}')\n"
            "cluster = dba.create_cluster('{}', {{'autoRejoinTries': '{}', "
            "'expelTimeout': '{}', 'ipAllowlist': '{}'}})"
            .format(
                self.cluster_user, self.cluster_password, self.cluster_address,
                self.options.cluster_name, self.options.auto_rejoin_tries,
                self.options.expel_timeout, self.generate_ip_allowlist_str()
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
        leadership.leader_set({
            make_cluster_instance_clustered_key(self.cluster_address): True})
        leadership.leader_set({"cluster-created": str(uuid.uuid4())})

    def set_cluster_option(self, key, value):
        """Set an option on the cluster

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

    def get_ip_allowlist_str_from_db(self, m_helper=None):
        """Helper for retrieving ip allow list

        :param m_helper: Helper for connecting to DB.
        :type m_helper: mysql.MySQL8Helper
        :returns: Current setting of group_replication_ip_allowlist
        :rtype: str
        """
        if not m_helper:
            m_helper = self.get_db_helper()
            m_helper.connect(password=self.mysql_password)
        query_out = m_helper.select(
            "SHOW GLOBAL VARIABLES LIKE 'group_replication_ip_allowlist'")
        assert len(query_out) == 1 and len(query_out[0]) == 2, \
            "ip allowlist query returned unexpected result: {}".format(
                query_out)
        return query_out[0][1]

    def get_ip_allowlist_list_from_db(self, m_helper=None):
        """Extract group_replication_ip_allowlist from db.

        :param m_helper: Helper for connecting to DB.
        :type m_helper: mysql.MySQL8Helper
        :returns: Current setting of group_replication_ip_allowlist
        :rtype: List[str]
        """
        allow_list = self.get_ip_allowlist_str_from_db(m_helper=m_helper)
        return allow_list.split(',')

    def is_address_in_replication_ip_allowlist(self, address,
                                               ip_allowlist=None):
        """Check if address is in ip allow list.

        :param address: IP address to check against.
        :type address: str
        :param ip_allowlist: IP/CIDRs to check against.
        :type ip_allowlist: List[str]
        :returns: Whether address is allowed to connect to cluster.
        :rtype: Boolean
        """
        ip_allowlist = ip_allowlist or self.get_ip_allowlist_list_from_db()
        allowed = False
        for net in ip_allowlist:
            if net == 'AUTOMATIC':
                if ipaddress.ip_address(address).is_private:
                    allowed = True
            elif ch_net_ip.is_address_in_network(net, address):
                allowed = True
        return allowed

    def get_denied_peers(self):
        """List of peer units that are not in the IP allow list.

        :returns: Units which are not permitted to connect to cluster.
        :rtype: List[str]
        """
        ip_allowlist = self.get_ip_allowlist_list_from_db()
        denied_peers = []
        for addr in self.cluster_peer_addresses:
            if not self.is_address_in_replication_ip_allowlist(addr,
                                                               ip_allowlist):
                denied_peers.append(addr)
        return denied_peers

    def add_instance_to_cluster(self, address):
        """Add MySQL instance to the cluster.

        :param address: Address of the MySQL instance to be clustered
        :type address: str
        :side effect: Calls self.run_mysqlsh_script
        :returns: This function is called for its side effect
        :rtype: None
        """
        if reactive.is_flag_set(
                "leadership.set.{}"
                .format(make_cluster_instance_clustered_key(address))):
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
            "{{'recoveryMethod': 'clone', 'waitRecovery': '2', "
            "'interactive': False, 'ipAllowlist': '{allowlist}'}})"
            .format(
                user=self.cluster_user, pw=self.cluster_password,
                caddr=_primary or self.cluster_address,
                name=self.options.cluster_name, addr=address,
                allowlist=self.generate_ip_allowlist_str()))
        try:
            output = self.run_mysqlsh_script(_script)
        except subprocess.CalledProcessError as e:
            # LP Bug#1912688
            # When the recoveryMethod clone actually needs to overwrite the
            # remote node the mysql-shell unfortunately returns with returncode
            # 1. Both "Clone process has finished" and "Group Replication is
            # running" actually indicate successful states.
            # Creating separate checks in order to get good logging on each
            # outcome.
            output = None
            _stderr = e.stderr.decode("UTF-8")
            if "Clone process has finished" in _stderr:
                output = e.stderr
                ch_core.hookenv.log(
                    "Add instance {} raised CalledProcessError with "
                    "returncode 1, however, the output contains 'Clone "
                    "process has finished' an indication of successfully "
                    "adding the instance to the cluster."
                    .format(address), "WARNING")
            if "Group Replication is running" in _stderr:
                output = e.stderr
                ch_core.hookenv.log(
                    "Add instance {} raised CalledProcessError with "
                    "returncode 1, however, the output contains 'Group "
                    "Replication is running' an indication of previously "
                    "successfully adding the instance to the cluster."
                    .format(address), "WARNING")
            # Some failure has occured, return without setting instance
            # clustered flag.
            if not output:
                ch_core.hookenv.log(
                    "Failed adding instance {} to cluster: {}"
                    .format(address, _stderr), "ERROR")
                return
        ch_core.hookenv.log("Instance Clustered {}: {}"
                            .format(address, output.decode("UTF-8")),
                            level="DEBUG")
        leadership.leader_set({
            make_cluster_instance_clustered_key(address): True})

    def restart_instance(self, address):
        """Restart instance

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

        :side effect: Calls self.run_mysqlsh_script
        :returns: This function is called for its side effect
        :rtype: None
        """
        _primary = self.get_cluster_primary_address(nocache=True)
        ch_core.hookenv.log("Remove instance: {}.".format(address))
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
            # Clear flags to avoid LP Bug#1922394
            if ch_core.hookenv.is_leader():
                self.clear_flags_for_removed_instance(address)
            else:
                ch_core.hookenv.log(
                    "Unable to clear {} and {} flags as this is not the "
                    "leader unit. Run leader-set manually on the leader and "
                    "set these values to None to avoid LP Bug#1922394"
                    .format(
                        make_cluster_instance_configured_key(address),
                        make_cluster_instance_clustered_key(address)),
                    "WARNING")
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
            if not self.create_user(
                    unit.received['cluster-address'],
                    unit.received['cluster-user'],
                    unit.received['cluster-password'],
                    "all"):
                raise Exception(
                    "Not all cluster users created.")
        self.configure_instance(address)
        self.add_instance_to_cluster(address)

    def get_cluster_status(self, nocache=False):
        """Get cluster status

        Return cluster.status() as a dictionary. If cached data exists and is
        not explicity avoided with the nocache parameter, avoid the expensive
        DB query.

        :param nocache: Do not return cached data
        :type nocache: Boolean
        :side effect: Calls self.check_mysql_connection
        :returns: Dictionary cluster status output
        :rtype: Union[None, dict]
        """
        # Speed up when we are not yet clustered
        if not reactive.is_flag_set(
                "leadership.set.{}"
                .format(make_cluster_instance_clustered_key(
                    self.cluster_address))):
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
                .format(self._error_str(e)), "ERROR")
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
                .format(self._error_str(e)), "ERROR")
            return
        self._cached_cluster_status = json.loads(output.decode("UTF-8"))
        return self._cached_cluster_status

    @staticmethod
    def _error_str(e):
        """Get error string, if possible, from a subprocess CalledProcessError.

        Try to get the stderr from a CalledProcessError object, but if it's
        None (or it is a different exception), just stringify the error.
        (due to bug LP#2015368)

        :param e: the Exception that occured.
        :type e: Exception or derived Exception
        :returns: the string for the error.
        :rtype: str
        """
        try:
            return e.stderr.decode()
        except Exception:
            pass
        return str(e)

    def get_cluster_primary_address(self, nocache=False):
        """Get cluster RW primary address.

        Return cluster.status()['groupInformationSourceMember'] which is the
        primary R/W node in the cluster.  This node is safe to use for writes
        to the cluster.

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
            return None
        try:
            return _status["defaultReplicaSet"]["statusText"]
        except KeyError:
            # BUG LP:#2020216 - as a failsafe, if either key is missing just
            # return None.
            pass
        return None

    def get_cluster_instance_mode(self, nocache=False):
        """Get cluster status mode

        Return cluster.status()["defaultReplicaSet"]["topology"]. This will be
        "R/W" or "R/O" depending on the mode of this instance in the cluster.
        If cached data exists and is not explicity avoided with the nocache
        parameter, avoid the call to self.get_cluster_status.

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
        try:
            return (_status["defaultReplicaSet"]["topology"]
                    ["{}:{}".format(self.cluster_address, self.cluster_port)]
                    ["mode"])
        except KeyError:
            # BUG LP:#2020216 - during db-router-relation-departed the
            # address:port combination can be missing depending on the order of
            # the relations that fire during removal of this unit. Thus return
            # None in the case of a KeyError
            pass
        return None

    # TODO: Generalize and move to mysql charmhelpers
    def get_allowed_units(self, database, username, relation_id,
                          db_helper=None, prefix=None):
        """Get Allowed Units.

        Call MySQL8Helper.get_allowed_units and return space delimited list of
        allowed unit names.

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
        if not rw_helper:
            ch_core.hookenv.log(
                "create_databases_and_users: the rw helper for the cluster is "
                "not available and so skipping create_databases_and_users",
                "WARNING")
            return False
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
            ("leadership.set.{}"
             .format(make_cluster_instance_configured_key(
                 self.cluster_address)),
             "waiting",
             "Instance not yet configured for clustering"),
            ("leadership.set.cluster-created",
             "waiting",
             "Cluster {} not yet created by leader"
             .format(self.cluster_name)),
            ("leadership.set.cluster-instances-configured",
             "waiting",
             "Not all instances configured for clustering"),
            ("leadership.set.{}"
             .format(make_cluster_instance_clustered_key(
                 self.cluster_address)),
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

        :side effect: Calls status_set
        :returns: This function is called for its side effect
        :rtype: None
        """
        # This unit is departing the cluster
        # This overrides everything else.
        # Stop processing any other information.
        if reactive.is_flag_set("local.cluster.unit.departing"):
            ch_core.hookenv.status_set(
                "waiting", "This unit is departing. Shutting down.")
            return

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
        # LP Bug #1917337
        if _cluster_status is None:
            ch_core.hookenv.status_set(
                "blocked",
                "Cluster is inaccessible from this instance. "
                "Please check logs for details.")
            return

        # Check all peers are allowed to connect to this unit
        denied_peers = self.get_denied_peers()
        if denied_peers:
            ch_core.hookenv.status_set(
                "blocked",
                "Units not allowed to replicate with this unit: {}. See "
                "update-unit-acls action.".format(
                    ",".join(denied_peers)))
            return

        if "OK" not in _cluster_status:
            ch_core.hookenv.status_set(
                "blocked",
                "MySQL InnoDB Cluster not healthy: {}"
                .format(self.get_cluster_status_text() or "(empty)"))
            return

        # All is good. Report this instance's mode to workgroup status
        ch_core.hookenv.status_set(
            "active",
            "Unit is ready: Mode: {}, {}"
            .format(self.get_cluster_instance_mode() or "(Unknown)",
                    self.get_cluster_status_text() or "(empty)"))

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
                 "--ignore-table=mysql.event",
                 "--set-gtid-purged=COMMENTED"]
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
                    # Mysql InnodB Cluster uses coordinator for rolling
                    # restarts. Request a restart.
                    ch_core.hookenv.log(
                        "Acquiring config-changed-restart lock for TLS change",
                        "DEBUG")
                    coordinator.acquire('config-changed-restart')
            else:
                reactive.clear_flag('tls.enabled')

    def depart_instance(self):
        """Depart from the cluster.

        Cleanly stop MySQL giving the other nodes in the cluster notification
        that this node is down. Disable MySQL so it does not accidently start.
        Update the cluster relation indicating this node is no longer in the
        cluster.

        :side effect: Stops MySQL and unsets relation data
        :returns: This function is called for its side effect
        :rtype: None
        """
        ch_core.hookenv.log("Stopping mysql ...", "WARNING")
        ch_core.host.service_stop(self.default_service)
        ch_core.hookenv.log("Disabling mysql ...", "WARNING")
        subprocess.check_call(["update-rc.d", self.default_service, "disable"])

        # Note: Keeping cluster-address set as the leader unit will use this to
        # clean up.
        ch_core.hookenv.log("Unsetting cluster values ...", "WARNING")
        if self.cluster_relation_endpoint:
            self.cluster_relation_endpoint.peer_relation.to_publish_raw[
                'cluster-user'] = None
            self.cluster_relation_endpoint.peer_relation.to_publish_raw[
                'cluster-password'] = None
        if ch_core.hookenv.is_leader():
            self.clear_flags_for_removed_instance(self.cluster_address)

    def clear_flags_for_removed_instance(self, address):
        """Clear leadership flags for a removed or departed instance.

        When an instance is removed or departed, if the leader settings for
        cluster-instance-configured-<IP> and cluster-instance-clustered-<IP>
        are not removed and a new instance happens to have the same IP it will
        never be joined the cluster.

        Clear the flags to allow the introduction of a new instance with the
        same IP.

        :param address: Address of the MySQL instance to remove flags for
        :type address: str
        :side effect: Calls leader set
        :returns: This function is called for its side effect
        :rtype: None
        """
        if not ch_core.hookenv.is_leader():
            ch_core.hookenv.log(
                "Clear leadership flags for removed instance with address {} "
                "called on a non-leader node. Flags are not unset and may "
                "require the remove-instance action.", "WARNING")
            return

        # Clear flags to avoid LP Bug#1922394
        leadership.leader_set({
            make_cluster_instance_configured_key(address): None,
            make_cluster_instance_clustered_key(address): None})

    def update_dotted_flags(self):
        """Update leadership settings for cluster flags with dotted names.

        Called during update-status hook.
        Due to a bug in Juju the flags the charm previously used like the
        following could not be unset:

           cluster-instance-clustered-10.5.5.1
           cluster-instance-configured-10.5.5.1

        Update leader settings for all cluster-* flags that have dots in
        their names. These updated flags can then be unset when an instance
        is removed.

        :side effect: Calls leader set
        :returns: This function is called for its side effect
        :rtype: None
        """
        if not ch_core.hookenv.is_leader():
            ch_core.hookenv.log(
                "Update dotted flags called on a non-leader node. Bailing.",
                "WARNING")
            return

        _leader_settings = ch_core.hookenv.leader_get()
        _new_leader_settings = {}
        for key in _leader_settings.keys():
            # Don't update mysql.passwd
            if key.startswith("cluster") and "." in key:
                # Clear the dotted version
                _new_leader_settings[key] = None
                # Set the hyphenated version
                _new_leader_settings[key.replace(".", "-")] = (
                    _leader_settings[key])
            else:
                _new_leader_settings[key] = _leader_settings[key]

        leadership.leader_set(_new_leader_settings)

    @tenacity.retry(wait=tenacity.wait_fixed(6),
                    reraise=True,
                    stop=tenacity.stop_after_attempt(5),
                    retry=tenacity.retry_if_exception_type(ValueError))
    def wait_for_cluster_state(self, m_helper, node_address, target_state):
        """Wait for replication member to reach given state.

        Wait for a given member of the cluster, indicated by node_address, to
        be in the target_state.

        :param m_helper: Helper for connecting to DB.
        :type m_helper: mysql.MySQL8Helper
        :param node_address: IP address of node to query.
        :type node_address: str
        :param target_state: State to wait for.
        :type target_state: str
        :raises: ValueError
        """
        CLUSTER_QUERY = """
        SELECT MEMBER_STATE
        FROM performance_schema.replication_group_members
        where MEMBER_HOST='{address}'
        """
        query_out = m_helper.select(CLUSTER_QUERY.format(address=node_address))
        assert len(query_out) == 1 and len(query_out[0]) == 1, \
            "Cluster query returned unexpected result for {}: {}".format(
                node_address,
                query_out)
        if query_out[0][0] != target_state:
            raise ValueError

    def get_clustered_addresses(self):
        """Get the cluster addresses of all units which have joined cluster.

        :returns: List of IP addresses
        :rtype: List[str]
        """
        _leader_settings = ch_core.hookenv.leader_get()
        all_addresses = self.cluster_peer_addresses
        all_addresses.append(self.cluster_address)
        clustered_addresses = []
        for address in all_addresses:
            leader_key = make_cluster_instance_clustered_key(address)
            _value = _leader_settings.get(leader_key)
            if _value and ch_core.strutils.bool_from_string(_value):
                clustered_addresses.append(address)
        return clustered_addresses

    def update_acls(self):
        """Update IP allow list on each node in cluster.

        Update IP allow list on each node in cluster. At present this can only
        be done when replication is stopped.
        """
        ip_allow_list = self.generate_ip_allowlist_str()
        for address in self.get_clustered_addresses():
            m_helper = mysql.MySQL8Helper(
                'unused',
                'unused',
                host=address,
                migrate_passwd_to_leader_storage=False,
                delete_ondisk_passwd_file=False,
                user=self.cluster_user,
                password=self.cluster_password)
            # Bug in helper causes it to use root user irrespective of the user
            # setting when mysql.MySQL8Helper is instantiated.
            m_helper.connect(user=self.cluster_user)
            current_allow_list = self.get_ip_allowlist_str_from_db(
                m_helper)
            if current_allow_list == ip_allow_list:
                ch_core.hookenv.log(
                    ("group_replication_ip_allowlist does not need updating "
                     "on {}").format(address),
                    "DEBUG")
            else:
                m_helper.execute("STOP GROUP_REPLICATION")
                self.wait_for_cluster_state(m_helper, address, 'OFFLINE')
                m_helper.execute(
                    "SET GLOBAL group_replication_ip_allowlist = '{}'".format(
                        ip_allow_list))
                m_helper.execute("START GROUP_REPLICATION")
                self.wait_for_cluster_state(m_helper, address, 'ONLINE')

    PASSWORD_PATTERNS = (re.compile(r"^mysql-(.*)\.passwd$"),
                         re.compile(r"^(.*)\.passwd$"))

    def get_service_usernames(self):
        """Provide a list of service usernames that can be rotated.

        :returns: list of service names
        :rtype: List[str]
        """
        usernames = set()
        for key in ch_core.hookenv.leader_get().keys():
            for pattern in self.PASSWORD_PATTERNS:
                match = pattern.match(key)
                if match:
                    username = match[1]
                    if username != "mysql":
                        usernames.add(username)
                    break
        return sorted(usernames)

    def rotate_service_user_passwd(self, service_username, db_router):
        """Rotate the passed service user password.

        Rotate the password for the service user specified.  It must be one of
        the usernames returned by `get_service_usernames()`; otherwise an error
        is generated.

        :param service_username: the service user to rotate the passord for.
        :type service_username: str
        :param db_router: the db_router interface
        :type db_router: Optional[reactive.relations.Endpoint]
        :raises: exceptions.InvalidServiceUserError if the service username
            isn't allowed to be rotated.
        :raises: exceptions.NotLeaderError if the unit is not the leader.
        """
        if not ch_core.hookenv.is_leader():
            raise exceptions.NotLeaderError()
        valid_usernames = self.get_service_usernames()
        if service_username not in valid_usernames:
            raise exceptions.InvalidServiceUserError()

        # use the cluster helper, as this will write the password across the
        # cluster.
        m_helper = self.get_cluster_rw_db_helper()
        if not m_helper:
            ch_core.hookenv.log(
                "Can't get a cluster rw helper, which is needed for password "
                "rotations.",
                "DEBUG")
            raise exceptions.NotInCluster()

        # get a list of the hosts for the user.
        user_hosts = m_helper.user_host_list()
        ch_core.hookenv.log(
            "User host lists = {}".format(", ".join(
                ("{}@{}".format(u, h) for u, h in user_hosts))),
            "DEBUG")
        # find the hosts that match the user
        service_user_hosts = [h for u, h in user_hosts
                              if u == service_username]

        # create the new password; 32 chars is in line with password creation
        # in charm-helpers for mysql.
        new_passwd = ch_core.host.pwgen(length=32)

        # Update the password in the database for the users
        m_helper.set_mysql_password_using_current_connection(
            service_username, new_passwd, service_user_hosts)

        # Now that the database is updated, update the relation data.
        if db_router is None:
            ch_core.hookenv.log(
                "No db_router relations made, so nothing to update.",
                "INFO")
            return
        # find the relation info for the service user.
        for unit in db_router.all_joined_units:
            db_data = mysql.get_db_data(
                dict(unit.received),
                unprefixed=self._unprefixed)
            for prefix, key_value in db_data.items():
                try:
                    username = key_value['username']
                except KeyError:
                    continue
                if username == service_username:
                    # This is the relation to update.
                    relation_key = ('password' if prefix == self._unprefixed
                                    else '{}_password'.format(prefix))
                    ch_core.hookenv.log(
                        "Setting password on relation {} on key {}"
                        .format(unit.relation.relation_id, relation_key),
                        "DEBUG")
                    db_router.relations[
                        unit.relation.relation_id].to_publish_app[
                            relation_key] = new_passwd
