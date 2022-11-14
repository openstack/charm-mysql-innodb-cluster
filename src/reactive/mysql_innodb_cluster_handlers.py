import json

import charms.reactive as reactive
import charms.leadership as leadership

import charms_openstack.bus
import charms_openstack.charm as charm

import charmhelpers.core as ch_core
import charmhelpers.contrib.openstack.cert_utils as cert_utils

import charms.coordinator as coordinator
import charm.openstack.mysql_innodb_cluster as mysql_innodb_cluster  # noqa

from .prometheus_mysql_exporter_handlers import (
    create_remote_prometheus_exporter_user
)

charms_openstack.bus.discover()

charm.use_defaults('update-status')


@reactive.hook('upgrade-charm')
def custom_upgrade_charm():
    """Custom upgrade charm.

    Fix old style dotted flag names during upgrade-charm hook
    """
    with charm.provide_charm_instance() as instance:
        if reactive.is_flag_set('leadership.is_leader'):
            # Change leadership cluster flags with dots in their names
            instance.update_dotted_flags()
            if (reactive.is_flag_set(
                    'leadership.set.cluster-instances-clustered') and
                    reactive.is_flag_set('db-router.available')):
                db_router = reactive.endpoint_from_flag("db-router.available")
                # Deliver fix for bug LP#1989505
                instance.create_databases_and_users(db_router)
        instance.upgrade_charm()
        instance.assess_status()


@reactive.when('leadership.is_leader')
@reactive.when('snap.installed.mysql-shell')
@reactive.when_not('charm.installed')
def leader_install():
    """Leader install.

    Set passwords and install MySQL packages.
    """
    with charm.provide_charm_instance() as instance:
        instance.install()
        reactive.set_flag("charm.installed")
        instance.assess_status()


@reactive.when('leadership.set.mysql.passwd')
@reactive.when_not('leadership.is_leader')
@reactive.when_not('charm.installed')
def non_leader_install():
    """Non-leader install.

    Wait until the leader node has set passwords before installing the MySQL
    packages.
    """
    # Wait for leader to set mysql.passwd
    with charm.provide_charm_instance() as instance:
        instance.install()
        reactive.set_flag("charm.installed")
        instance.assess_status()


@reactive.when('charm.installed')
@reactive.when_not('local.cluster.user-created')
def create_local_cluster_user():
    """Create local cluster user in the DB.
    """
    ch_core.hookenv.log("Creating local cluster user.", "DEBUG")
    with charm.provide_charm_instance() as instance:
        if not instance.create_user(
                instance.cluster_address,
                instance.cluster_user,
                instance.cluster_password,
                "all",
        ):
            ch_core.hookenv.log("Local cluster user was not created.",
                                "WARNING")
            return
        reactive.set_flag("local.cluster.user-created")
        instance.assess_status()


@reactive.when('local.cluster.user-created')
@reactive.when('cluster.connected')
@reactive.when_not('cluster.available')
def send_cluster_connection_info():
    """Send cluster connection information.

    Send cluster user, password and address information over the cluster
    relation on how to connect to this unit.

    :param cluster: Cluster interface
    :type cluster: MySQLInnoDBClusterPeers object
    """
    cluster = reactive.endpoint_from_flag("cluster.connected")
    ch_core.hookenv.log("Send cluster connection information.", "DEBUG")
    with charm.provide_charm_instance() as instance:
        cluster.set_cluster_connection_info(
            instance.cluster_address,
            instance.cluster_user,
            instance.cluster_password)
        instance.assess_status()


@reactive.when_not('local.cluster.all-users-created')
@reactive.when('cluster.available')
def create_remote_cluster_user():
    """Create remote cluster user.

    Create the remote cluster peer user and grant cluster permissions in the
    MySQL DB.

    :param cluster: Cluster interface
    :type cluster: MySQLInnoDBClusterPeers object
    """
    cluster = reactive.endpoint_from_flag("cluster.available")
    ch_core.hookenv.log("Creating remote users.", "DEBUG")
    with charm.provide_charm_instance() as instance:
        for unit in cluster.all_joined_units:
            if not instance.create_user(
                    unit.received['cluster-address'],
                    unit.received['cluster-user'],
                    unit.received['cluster-password'],
                    "all"):
                ch_core.hookenv.log("Not all remote users created.", "WARNING")
                return

        # Optimize clustering by causing a cluster relation changed
        cluster.set_unit_configure_ready()
        reactive.set_flag('local.cluster.all-users-created')
        instance.assess_status()


@reactive.when('cluster.available')
def check_quorum():
    """Check that all units have sent their cluster address.

    When the cluster is created an ip allow list is set. This cannot be
    updated while replication is running. To avoid the need to update
    it after cluster creation wait for all cluster addresses to be present.
    NOTE: The update-unit-acls action can be run if a unit on a new subnet
          is added to an existing cluster.
    """
    with charm.provide_charm_instance() as instance:
        if instance.reached_quorum():
            ch_core.hookenv.log("Reached quorum", "DEBUG")
            reactive.set_flag('local.cluster.quorum-reached')
        else:
            ch_core.hookenv.log("Quorum not reached", "DEBUG")


@reactive.when('local.cluster.quorum-reached')
@reactive.when('leadership.is_leader')
@reactive.when('local.cluster.user-created')
@reactive.when_not('leadership.set.cluster-created')
def initialize_cluster():
    """Initialize the cluster.

    Create the InnoDB cluster.
    """
    ch_core.hookenv.log("Initializing InnoDB cluster.", "DEBUG")
    with charm.provide_charm_instance() as instance:
        instance.configure_instance(instance.cluster_address)
        instance.create_cluster()
        instance.assess_status()


@reactive.when('leadership.is_leader')
@reactive.when('leadership.set.cluster-created')
@reactive.when('local.cluster.all-users-created')
@reactive.when('cluster.available')
@reactive.when_not('leadership.set.cluster-instances-configured')
def configure_instances_for_clustering():
    """Configure cluster peers for clustering.

    Prepare peers to be added to the cluster.

    :param cluster: Cluster interface
    :type cluster: MySQLInnoDBClusterPeers object
    """
    cluster = reactive.endpoint_from_flag("cluster.available")
    ch_core.hookenv.log("Configuring instances for clustering.", "DEBUG")
    with charm.provide_charm_instance() as instance:
        for unit in cluster.all_joined_units:
            if unit.received['unit-configure-ready']:
                instance.configure_instance(
                    unit.received['cluster-address'])
                instance.add_instance_to_cluster(
                    unit.received['cluster-address'])
        # Verify all are configured
        for unit in cluster.all_joined_units:
            if not reactive.is_flag_set(
                "leadership.set.{}"
                .format(
                    mysql_innodb_cluster.make_cluster_instance_configured_key(
                        unit.received['cluster-address']))):
                return
        # All have been configured
        leadership.leader_set(
            {"cluster-instances-configured": True})
        instance.assess_status()


@reactive.when('leadership.is_leader')
@reactive.when('leadership.set.cluster-created')
@reactive.when('leadership.set.cluster-instances-configured')
@reactive.when('cluster.available')
@reactive.when_not('leadership.set.cluster-instances-clustered')
def add_instances_to_cluster():
    """Add cluster peers to the cluster.

    :param cluster: Cluster interface
    :type cluster: MySQLInnoDBClusterPeers object
    """
    cluster = reactive.endpoint_from_flag("cluster.available")
    ch_core.hookenv.log("Adding instances to cluster.", "DEBUG")
    with charm.provide_charm_instance() as instance:
        for unit in cluster.all_joined_units:
            instance.add_instance_to_cluster(
                unit.received['cluster-address'])

        # Verify all are clustered
        for unit in cluster.all_joined_units:
            if not reactive.is_flag_set(
                "leadership.set.{}"
                .format(
                    mysql_innodb_cluster.make_cluster_instance_clustered_key(
                        unit.received['cluster-address']))):
                return
        # All have been clustered
        leadership.leader_set(
            {"cluster-instances-clustered": True})
        instance.assess_status()


@reactive.when_not('leadership.is_leader')
@reactive.when('leadership.set.cluster-created')
@reactive.when('cluster.available')
def signal_clustered():
    """Signal unit clustered to peers.

    Set this unit clustered on the cluster peer relation.

    :param cluster: Cluster interface
    :type cluster: MySQLInnoDBClusterPeers object
    """
    cluster = reactive.endpoint_from_flag("cluster.available")
    # Optimize clustering by causing a cluster relation changed
    with charm.provide_charm_instance() as instance:
        if reactive.is_flag_set(
                "leadership.set.{}"
                .format(
                    mysql_innodb_cluster.make_cluster_instance_clustered_key(
                        instance.cluster_address))):
            cluster.set_unit_clustered()
        instance.assess_status()


@reactive.when('leadership.set.cluster-instances-clustered')
@reactive.when('config.changed')
def config_changed():
    ch_core.hookenv.log(
        "Acquiring config-changed-restart lock in config_changed", "DEBUG")
    coordinator.acquire('config-changed-restart')
    if reactive.is_flag_set('leadership.is_leader'):
        with charm.provide_charm_instance() as instance:
            instance.configure_tls()
            instance.render_all_configs()
            instance.wait_until_cluster_available()
            if reactive.is_flag_set('config.changed.auto-rejoin-tries'):
                instance.set_cluster_option(
                    "autoRejoinTries", instance.options.auto_rejoin_tries)
            if reactive.is_flag_set('config.changed.expel-timeout'):
                instance.set_cluster_option(
                    "expelTimeout", instance.options.expel_timeout)
    else:
        with charm.provide_charm_instance() as instance:
            try:
                instance.wait_until_cluster_available()
            except Exception:
                ch_core.hookenv.log(
                    "Cluster was not availble as expected.", "WARNING")


@reactive.when('coordinator.granted.config-changed-restart')
def config_changed_restart():
    """Coordinated config change and restart."""
    ch_core.hookenv.log("Coordinated config_changed_restart", "DEBUG")
    with charm.provide_charm_instance() as instance:
        ch_core.hookenv.status_set(
            'maintenance', 'Rolling config changed and restart.')
        instance.configure_tls()
        instance.render_all_configs()


@reactive.when('leadership.is_leader')
@reactive.when('leadership.set.cluster-instances-clustered')
@reactive.when('db-router.available')
@reactive.when('coordinator-released-config-changed-restart-lock')
def post_rolling_restart_update_clients():
    """After rolling restart kick off a client update."""
    ch_core.hookenv.log(
        "Coordinated post rolling restart client update", "DEBUG")
    db_router_respond()
    reactive.clear_flag('coordinator-released-config-changed-restart-lock')


@reactive.when('leadership.is_leader')
@reactive.when('leadership.set.cluster-instances-clustered')
@reactive.when('endpoint.shared-db.changed')
@reactive.when('shared-db.available')
@reactive.when_none(
    'charm.paused', 'local.cluster.unit.departing')
def shared_db_respond():
    """Respond to Shared DB Requests.
    """
    ch_core.hookenv.log(
        "The share-db relation is DEPRECATED. "
        "Please use mysql-router and the db-router relation.",
        "WARNING")
    shared_db = reactive.endpoint_from_flag("shared-db.available")
    with charm.provide_charm_instance() as instance:
        if instance.create_databases_and_users(shared_db):
            ch_core.hookenv.log(
                "Shared DB relation created DBs and users.", "DEBUG")
            reactive.clear_flag('endpoint.shared-db.changed')
        instance.assess_status()


@reactive.when('leadership.is_leader')
@reactive.when('leadership.set.cluster-instances-clustered')
@reactive.when('endpoint.db-router.changed')
@reactive.when('db-router.available')
@reactive.when_none(
    'charm.paused', 'local.cluster.unit.departing')
def db_router_respond():
    """Respond to DB Router Requests.
    """
    ch_core.hookenv.log("DB router respond", "DEBUG")
    db_router = reactive.endpoint_from_flag("db-router.available")
    with charm.provide_charm_instance() as instance:
        if instance.create_databases_and_users(db_router):
            ch_core.hookenv.log(
                "DB Router relation created DBs and users.", "DEBUG")
            reactive.clear_flag('endpoint.db-router.changed')
        instance.assess_status()


@reactive.when('endpoint.cluster.changed.unit-configure-ready')
@reactive.when('leadership.set.cluster-instances-clustered')
@reactive.when('leadership.is_leader')
@reactive.when('cluster.available')
@reactive.when_not('local.cluster.unit.departing')
def scale_out():
    """Handle scale-out adding new nodes to an existing cluster."""

    ch_core.hookenv.log("Scale out: add new nodes.", "DEBUG")
    with charm.provide_charm_instance() as instance:
        if not reactive.is_flag_set(
                "leadership.set.{}"
                .format(
                    mysql_innodb_cluster.make_cluster_instance_clustered_key(
                        instance.cluster_address))):
            ch_core.hookenv.log(
                "Unexpected edge case. This node is the leader but it is "
                "not yet clustered. As a non-cluster member it will not be "
                "able to join itself to the cluster. Run the 'add_instance' "
                "action on a member node with this unit's IP address to join "
                "this instance to the cluster.",
                "WARNING")
            return
    create_remote_cluster_user()

    if reactive.endpoint_from_flag("prometheus.available"):
        create_remote_prometheus_exporter_user()

    configure_instances_for_clustering()
    add_instances_to_cluster()
    reactive.clear_flag('endpoint.cluster.changed.unit-configure-ready')


@reactive.when('certificates.available')
@reactive.when('cluster.available')
@reactive.when_not('local.cluster.unit.departing')
def request_certificates():
    """When the certificates interface is available, request TLS certificates.
    """
    tls = reactive.endpoint_from_flag('certificates.available')
    with charm.provide_charm_instance() as instance:
        req = cert_utils.CertRequest(json_encode=False)
        req.add_hostname_cn()
        # Deploys will be using 127.0.0.1 with mysql-router, but still
        # validate the certificate.
        # Add localhost for mysql-router connections
        req.add_hostname_cn_ip([
            instance.cluster_address,
            instance.db_router_address,
            instance.shared_db_address,
            "127.0.0.1"])
        for cn, req in req.get_request().get('cert_requests', {}).items():
            tls.add_request_server_cert(cn, req['sans'])
        tls.request_server_certs()
        instance.assess_status()


@reactive.when_any(
    'certificates.ca.changed',
    'certificates.certs.changed',
    'endpoint.certificates.departed')
@reactive.when_not('local.cluster.unit.departing')
def configure_certificates():
    """When the certificates interface is available, this default handler
    updates on-disk certificates and switches on the TLS support.
    """
    tls = reactive.endpoint_from_flag('certificates.available')
    with charm.provide_charm_instance() as instance:
        instance.configure_tls(tls)
        # make charms.openstack required relation check happy
        reactive.set_flag('certificates.connected')
        for flag in 'certificates.ca.changed', 'certificates.certs.changed':
            if reactive.is_flag_set(flag):
                reactive.clear_flag(flag)
    instance.assess_status()


# Only react to cluster.departed
@reactive.when('endpoint.cluster.departed')
def scale_in():
    """ Handle scale in.

    Only react to cluster.departed, not any other departed hook nor a
    cluster.broken hook. Cluster.departed is only executed once on any given
    node. We want to shutdown and clean up only in a graceful departing
    scenario. The remove-instance action will function for all other scenarios.

    If this is the node departing, stop services and notify peers. If this is
    the leader node and not the departing node, attempt to remove the instance
    from cluster metdata.
    """
    # Intentionally using the charm helper rather than the interface to
    # guarantee we get only the departing instance's cluster-address
    _departing_address = ch_core.hookenv.relation_get("cluster-address")
    _departing_unit = ch_core.hookenv.departing_unit()
    if not _departing_unit:
        ch_core.hookenv.log(
            "In a cluster departing hook but departing unit is unset. "
            "Doing nothing.", "WARNING")
        return

    with charm.provide_charm_instance() as instance:
        if ch_core.hookenv.local_unit() == _departing_unit:
            # If this is the departing unit stop mysql and attempt a clean
            # departure.
            ch_core.hookenv.log(
                "{} is this unit departing. Shutting down."
                .format(_departing_unit),
                "WARNING")
            reactive.set_flag("local.cluster.unit.departing")
            instance.depart_instance()
            if reactive.is_flag_set('leadership.is_leader'):
                ch_core.hookenv.log(
                    "Since this departing instance is the juju leader node it "
                    "is not possible to automatically remove it from cluster "
                    "metadata. Run the remove-instance action on the newly "
                    "elected leader with address={} to remove it from cluster "
                    "metadata and clear flags."
                    .format(instance.cluster_address),
                    "WARNING")
        elif reactive.is_flag_set('leadership.is_leader'):
            # Attempt to clean up departing unit.
            # If the departing unit's IP remains in cluster metadata as seen in
            # the cluster-status action, run the remove-instance action with
            # the "MISSING" instance's IP.
            if _departing_address:
                ch_core.hookenv.log(
                    "Automatically removing departing instance {} from "
                    "cluster metadata."
                    .format(_departing_address), "WARNING")
                instance.remove_instance(
                    json.loads(_departing_address), force=True)
            else:
                ch_core.hookenv.log(
                    "Leader is unable to cleanly remove departing instance "
                    "{_du}. No cluster-address provided. Run remove-instance "
                    "address={_du} to clear cluster metadata and flags."
                    .format(_du=_departing_unit), "WARNING")


@reactive.when("leadership.is_leader")
@reactive.when("leadership.set.cluster-instances-clustered")
@reactive.when("db-monitor.connected")
@reactive.when_none("charm.paused", "local.cluster.unit.departing")
def db_monitor_respond():
    """Response to db-monitor relation changed."""
    ch_core.hookenv.log("db-monitor connected", ch_core.hookenv.DEBUG)
    db_monitor = reactive.endpoint_from_flag("db-monitor.connected")

    # get related application name = user
    username = related_app = ch_core.hookenv.remote_service_name()

    # get or create db-monitor user password
    db_monitor_stored_passwd_key = "db-monitor.{}.passwd".format(related_app)
    password = leadership.leader_get(db_monitor_stored_passwd_key)
    if not password:
        password = ch_core.host.pwgen()
        leadership.leader_set({db_monitor_stored_passwd_key: password})

    # provide relation data
    with charm.provide_charm_instance() as instance:
        # NOTE (rgildein): Create a custom user with administrator privileges,
        # but read-only access.
        if not instance.create_user(
                db_monitor.relation_ip, username, password, "read_only"
        ):
            ch_core.hookenv.log("db-monitor user was not created.",
                                ch_core.hookenv.WARNING)
            return

        db_monitor.provide_access(
            port=instance.cluster_port,
            user=username,
            password=password,
        )

        instance.assess_status()
