import charms.coordinator as coordinator
import charms.reactive as reactive
import charms.leadership as leadership

import charms_openstack.bus
import charms_openstack.charm as charm

import charmhelpers.core as ch_core

import charm.openstack.mysql_innodb_cluster as mysql_innodb_cluster  # noqa

charms_openstack.bus.discover()


charm.use_defaults(
    'update-status',
    'upgrade-charm',
    'certificates.available')


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
        instance.create_cluster_user(
            instance.cluster_address,
            instance.cluster_user,
            instance.cluster_password)
        reactive.set_flag("local.cluster.user-created")
        instance.assess_status()


@reactive.when('local.cluster.user-created')
@reactive.when('cluster.connected')
@reactive.when_not('cluster.available')
def send_cluster_connection_info(cluster):
    """Send cluster connection information.

    Send cluster user, password and address information over the cluster
    relation on how to connect to this unit.

    :param cluster: Cluster interface
    :type cluster: MySQLInnoDBClusterPeers object
    """
    ch_core.hookenv.log("Send cluster connection information.", "DEBUG")
    with charm.provide_charm_instance() as instance:
        cluster.set_cluster_connection_info(
            instance.cluster_address,
            instance.cluster_user,
            instance.cluster_password)
        instance.assess_status()


@reactive.when_not('local.cluster.all-users-created')
@reactive.when('cluster.available')
def create_remote_cluster_user(cluster):
    """Create remote cluster user.

    Create the remote cluster peer user and grant cluster permissions in the
    MySQL DB.

    :param cluster: Cluster interface
    :type cluster: MySQLInnoDBClusterPeers object
    """
    ch_core.hookenv.log("Creating remote users.", "DEBUG")
    with charm.provide_charm_instance() as instance:
        for unit in cluster.all_joined_units:
            instance.create_cluster_user(
                unit.received['cluster-address'],
                unit.received['cluster-user'],
                unit.received['cluster-password'])

        # Optimize clustering by causing a cluster relation changed
        cluster.set_unit_configure_ready()
        reactive.set_flag('local.cluster.all-users-created')
        instance.assess_status()


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
def configure_instances_for_clustering(cluster):
    """Configure cluster peers for clustering.

    Prepare peers to be added to the cluster.

    :param cluster: Cluster interface
    :type cluster: MySQLInnoDBClusterPeers object
    """
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
                    "leadership.set.cluster-instance-configured-{}"
                    .format(unit.received['cluster-address'])):
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
def add_instances_to_cluster(cluster):
    """Add cluster peers to the cluster.

    :param cluster: Cluster interface
    :type cluster: MySQLInnoDBClusterPeers object
    """
    ch_core.hookenv.log("Adding instances to cluster.", "DEBUG")
    with charm.provide_charm_instance() as instance:
        for unit in cluster.all_joined_units:
            instance.add_instance_to_cluster(
                unit.received['cluster-address'])

        # Verify all are clustered
        for unit in cluster.all_joined_units:
            if not reactive.is_flag_set(
                    "leadership.set.cluster-instance-clustered-{}"
                    .format(unit.received['cluster-address'])):
                return
        # All have been clustered
        leadership.leader_set(
            {"cluster-instances-clustered": True})
        instance.assess_status()


@reactive.when_not('leadership.is_leader')
@reactive.when('leadership.set.cluster-created')
@reactive.when('cluster.available')
def signal_clustered(cluster):
    """Signal unit clustered to peers.

    Set this unit clustered on the cluster peer relation.

    :param cluster: Cluster interface
    :type cluster: MySQLInnoDBClusterPeers object
    """
    # Optimize clustering by causing a cluster relation changed
    with charm.provide_charm_instance() as instance:
        if reactive.is_flag_set(
                "leadership.set.cluster-instance-clustered-{}"
                .format(instance.cluster_address)):
            cluster.set_unit_clustered()
        instance.assess_status()


@reactive.when('leadership.set.cluster-instances-clustered')
@reactive.when('config.changed')
def config_changed():
    if reactive.is_flag_set('leadership.is_leader'):
        with charm.provide_charm_instance() as instance:
            instance.render_all_configs()
            instance.wait_until_cluster_available()
            if reactive.is_flag_set('config.changed.auto-rejoin-tries'):
                instance.set_cluster_option(
                    "autoRejoinTries", instance.options.auto_rejoin_tries)
    else:
        with charm.provide_charm_instance() as instance:
            try:
                instance.wait_until_cluster_available()
            except:
                ch_core.hookenv.log(
                    "Cluster was not availble as expected.", "WARNING")
        ch_core.hookenv.log("Non-leader requst to restart.", "DEBUG")
        coordinator.acquire('config-changed-restart')


@reactive.when('coordinator.granted.config-changed-restart')
def config_changed_restart():
    with charm.provide_charm_instance() as instance:
        ch_core.hookenv.status_set(
            'maintenance', 'Rolling config changed and restart.')
        instance.render_all_configs()


@reactive.when('leadership.is_leader')
@reactive.when('leadership.set.cluster-instances-clustered')
@reactive.when('shared-db.available')
@reactive.when_not('charm.paused')
def shared_db_respond(shared_db):
    """Respond to Shared DB Requests.

    :param shared_db: Shared-DB interface
    :type shared-db: MySQLSharedProvides object
    """
    with charm.provide_charm_instance() as instance:
        instance.create_databases_and_users(shared_db)
        instance.assess_status()


@reactive.when('leadership.is_leader')
@reactive.when('leadership.set.cluster-instances-clustered')
@reactive.when('db-router.available')
@reactive.when_not('charm.paused')
def db_router_respond(db_router):
    """Respond to DB Router Requests.

    :param db_router: DB-Router interface
    :type db_router_interface: MySQLRouterRequires object
    """
    with charm.provide_charm_instance() as instance:
        instance.create_databases_and_users(db_router)
        instance.assess_status()
