# Overview

The mysql-innodb-cluster charm deploys a [MySQL 8][upstream-mysql8] InnoDB
clustered database. It is used in conjunction with the
[mysql-router][mysql-router-charm] charm.

> **Important**: The eoan series is the first series supported by the
  mysql-innodb-cluster and mysql-router charms. These charms replace the
  [percona-cluster][percona-cluster-charm] charm starting with the focal
  series.

# Usage

The charm is intended for deploying a cluster (minimum of three nodes) and
therefore does not deploy on a single unit.

## Configuration

See file `config.yaml` for the full list of configuration options, along with
their descriptions and default values.

## Deployment

To deploy a three-node cluster:

    juju deploy -n 3 mysql-innodb-cluster

The name of the cluster can be customized at deploy time:

    juju deploy -n 3 mysql-innodb-cluster --config cluster-name myCluster

Add a relation to a MySQL 8 Router (via the [db-router][db-router] endpoint):

    juju add-relation mysql-innodb-cluster:db-router msyql-router:db-router

A relation can be made to charms that use the [shared-db][shared-db] endpoint,
however this should be considered deprecated:

    juju add-relation mysql-innodb-cluster:shared-db keystone:shared-db

Nodes can be added to the cluster as Read Only nodes:

    juju add-unit mysql-innodb-cluster

See [OpenStack high availability][cdg-app-ha-mysql8] in the [OpenStack Charms
Deployment Guide][cdg] for more deploy instructions.

## Actions

This section lists Juju [actions][juju-docs-actions] supported by the charm.
Actions allow specific operations to be performed on a per-unit basis. To
display action descriptions run `juju actions mysql-innodb-cluster`. If the
charm is not deployed then see file `actions.yaml`.

* `add-instance`
* `cluster-rescan`
* `cluster-status`
* `mysqldump`
* `reboot-cluster-from-complete-outage`
* `rejoin-instance`
* `remove-instance`
* `restore-mysqldump`
* `set-cluster-option`

# Bugs

Please report bugs on [Launchpad][lp-bugs-charm-mysql-innodb-cluster].

For general charm questions refer to the [OpenStack Charm Guide][cg].

<!-- LINKS -->

[cg]: https://docs.openstack.org/charm-guide
[cdg]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide
[lp-bugs-charm-mysql-innodb-cluster]: https://bugs.launchpad.net/charm-mysql-innodb-cluster/+filebug
[juju-docs-actions]: https://jaas.ai/docs/actions
[percona-cluster-charm]: https://jaas.ai/percona-cluster
[mysql-router-charm]: https://jaas.ai/mysql-router
[upstream-mysql8]: https://dev.mysql.com/doc/refman/8.0/en/mysql-innodb-cluster-userguide.html
[db-router]: https://github.com/openstack-charmers/charm-interface-mysql-router
[shared-db]: https://github.com/openstack/charm-interface-mysql-shared
[cdg-app-ha-mysql8]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/latest/app-ha.html#mysql-8
