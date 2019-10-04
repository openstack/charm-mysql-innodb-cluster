import charms.reactive as reactive
import charms.leadership as leadership

import charms_openstack.bus
import charms_openstack.charm as charm

import charmhelpers.core as ch_core

import charm.mysql_innodb_cluster as mysql_innodb_cluster  # noqa

charms_openstack.bus.discover()


charm.use_defaults(
    'config.changed',
    'update-status',
    'upgrade-charm',
    'certificates.available')


@reactive.when_not('cluster-instances-clustered')
def debug():
    print("DEBUG")
    for flag in reactive.flags.get_flags():
        print(flag)


@reactive.when('leadership.is_leader')
@reactive.when('snap.installed.mysql-shell')
@reactive.when_not('charm.installed')
def leader_install():
    with charm.provide_charm_instance() as instance:
        instance.install()
        reactive.set_flag("charm.installed")
        instance.assess_status()


@reactive.when('leadership.set.root-password')
@reactive.when_not('leadership.is_leader')
@reactive.when_not('charm.installed')
def non_leader_install():
    # Wait for leader to set root-password
    with charm.provide_charm_instance() as instance:
        instance.install()
        reactive.set_flag("charm.installed")
        instance.assess_status()


@reactive.when('charm.installed')
@reactive.when_not('local.cluster.user-created')
def create_local_cluster_user():
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
    # Optimize clustering by causing a cluster relation changed
    with charm.provide_charm_instance() as instance:
        if reactive.is_flag_set(
                "leadership.set.cluster-instance-clustered-{}"
                .format(instance.cluster_address)):
            cluster.set_unit_clustered()
        instance.assess_status()


@reactive.when('leadership.is_leader')
@reactive.when('leadership.set.cluster-instances-clustered')
@reactive.when('shared-db.available')
def shared_db_respond(shared_db):
    with charm.provide_charm_instance() as instance:
        instance.create_databases_and_users(shared_db)
        instance.assess_status()


@reactive.when('leadership.is_leader')
@reactive.when('leadership.set.cluster-instances-clustered')
@reactive.when('db-router.available')
def db_router_respond(db_router):
    with charm.provide_charm_instance() as instance:
        instance.create_databases_and_users(db_router)
        instance.assess_status()
