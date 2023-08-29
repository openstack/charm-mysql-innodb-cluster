import subprocess
import charms.reactive as reactive
from charms.layer import snap
import charms_openstack.charm as charm
import charmhelpers.core as ch_core


SVC_NAME = "snap.mysqld-exporter.mysqld-exporter.service"
SNAP_NAME = "mysqld-exporter"


@reactive.when("prometheus.available")
@reactive.when("local.cluster.user-created")
@reactive.when_not("local.prom-exporter.user-created")
def create_local_prometheus_exporter_user():
    """Create local exporter user in the DB."""
    with charm.provide_charm_instance() as instance:
        if not instance.prometheus_exporter_password:
            ch_core.hookenv.log(
                "Local prometheus exporter user was not created, because the "
                "prometheus export password hasn't been set in the leader "
                "databag.",
                "WARNING")
            return
        if not instance.create_user(
            instance.cluster_address,
            instance.prometheus_exporter_user,
            instance.prometheus_exporter_password,
            "prom_exporter",
        ):
            ch_core.hookenv.log(
                "Local prometheus exporter user was not created.",
                "WARNING")
            return
        reactive.set_flag("local.prom-exporter.user-created")
        instance.assess_status()

    ch_core.hookenv.log(
        "Create prometheus mysql exporter user in the mysql db",
        "INFO")


@reactive.when_not("local.prom-exporter.all-user-created")
@reactive.when("prometheus.available")
@reactive.when("cluster.available")
@reactive.when("local.prom-exporter.user-created")
def create_remote_prometheus_exporter_user():
    """Create remote cluster user.

    Create the remote exporter peer user and grant exporter permissions in the
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
                    instance.prometheus_exporter_user,
                    instance.prometheus_exporter_password,
                    "prom_exporter"):
                ch_core.hookenv.log(
                    "Not all remote exporter users created.", "WARNING")
                return

        # Optimize clustering by causing a cluster relation changed
        cluster.set_unit_configure_ready()
        reactive.set_flag("local.prom-exporter.all-user-created")
        instance.assess_status()


@reactive.when("prometheus.available")
@reactive.when_not("snap.installed.prometheus-exporter")
def snap_install_prometheus_exporter():
    """Create local cluster user in the DB."""
    config = ch_core.hookenv.config()
    channel = config.get("prometheus-exporter-snap-channel", "stable")

    ch_core.hookenv.status_set(
        "maintenance",
        "Snap install {}. channel={}".format(SNAP_NAME, channel),
    )

    try:
        snap.install(SNAP_NAME, channel=channel, force_dangerous=False)

        reactive.set_flag("snap.installed.prometheus-exporter")

        ch_core.hookenv.log(
            "Snap install prometheus mysql exporter .",
            "INFO")
        ch_core.hookenv.status_set(
            "active",
            "Snap install {} success. channel={}".format(SNAP_NAME, channel),
        )
    except subprocess.CalledProcessError as e:
        ch_core.hookenv.status_set(
            "block",
            "Snap install {} fail. channel={}".format(SNAP_NAME, channel),
        )
        ch_core.hookenv.log(
            str(e),
            level=ch_core.hookenv.ERROR,
        )


def snap_config_prometheus_exporter(instance):
    """Snap config prometheus exporter."""
    # Connection information
    snap.set(SNAP_NAME, "mysql.user", instance.prometheus_exporter_user)
    snap.set(
        SNAP_NAME, "mysql.password", instance.prometheus_exporter_password)
    snap.set(SNAP_NAME, "mysql.host", instance.cluster_address)
    snap.set(SNAP_NAME, "mysql.port", instance.cluster_port)

    reactive.set_flag("snap.prometheus-exporter.configed")
    ch_core.hookenv.log(
        f"Config snap {SNAP_NAME}",
        "INFO",
    )


def start_prometheus_exporter():
    """Start service prometheus exporter."""
    ch_core.host.service_restart(SVC_NAME)
    reactive.set_flag("snap.prometheus-exporter.started")
    ch_core.hookenv.log(
        f"Start service {SVC_NAME}", "INFO")


@reactive.when("prometheus.available")
@reactive.when("snap.installed.prometheus-exporter")
@reactive.when("local.prom-exporter.user-created")
@reactive.when("local.prom-exporter.all-user-created")
@reactive.when_not("snap.prometheus-exporter.started")
def start_prometheus_exporter_service():
    """Start exporter service."""
    with charm.provide_charm_instance() as instance:
        if not reactive.is_flag_set("snap.prometheus-exporter.configed"):
            snap_config_prometheus_exporter(instance)
    start_prometheus_exporter()


@reactive.when("snap.prometheus-exporter.started")
@reactive.when("prometheus.available")
@reactive.when_not("local.prometheus.send-connection-info")
def send_prometheus_connection_info(target):
    """Configure http interface for prometheus."""
    with charm.provide_charm_instance() as instance:
        target.configure(
            port=instance.prometheus_exporter_port,
        )

    ch_core.hookenv.status_set(
        "active", "Start prometheus exporter service")
    ch_core.hookenv.log(
        "Prometheus connected", "INFO")
    reactive.set_flag("local.prometheus.send-connection-info")


@reactive.when("prometheus.available")
@reactive.when('config.changed')
def set_config_changed_snap_check():
    reactive.set_flag("snap.prometheus_exporter.check-config-changed")


@reactive.when("snap.prometheus_exporter.check-config-changed")
def maybe_update_snap_channel():
    # Stop service before snap update channel.
    # After exec stop_prometheus_exporter_service method,
    # the start_prometheus_exporter_service method should be triggered
    # next hook invocation.
    if ch_core.host.service_running(SVC_NAME):
        stop_prometheus_exporter_service()
    reactive.clear_flag("snap.prometheus_exporter.check-config-changed")


@reactive.when_not("prometheus.available")
@reactive.when("snap.prometheus-exporter.started")
def stop_prometheus_exporter_service():
    """Stop exporter service."""
    ch_core.host.service_stop(SVC_NAME)
    reactive.remove_state("snap.prometheus-exporter.configed")
    reactive.remove_state("snap.prometheus-exporter.started")
    ch_core.hookenv.status_set(
        "active", "Stop prometheus exporter service")
    ch_core.hookenv.log(
        "Stop service prometheus mysql exporter", "INFO")


@reactive.when_not("prometheus.available")
@reactive.when("local.prometheus.send-connection-info")
def prometheus_disconnected():
    ch_core.hookenv.status_set(
        "maintenance",
        "Stop prometheus exporter service",
    )
    reactive.remove_state("local.prometheus.send-connection-info")
    ch_core.hookenv.log(
        "Prometheus disconnect",
        "WARNING",
    )


@reactive.when("prometheus.available")
@reactive.when_not("local.prometheus.send-connection-info")
def prometheus_connected():
    ch_core.hookenv.status_set(
        "maintenance",
        "Start prometheus exporter service",
    )
    ch_core.hookenv.log(
        "Prometheus connect",
        "WARNING",
    )
