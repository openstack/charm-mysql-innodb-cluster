# Overview

This charm provides a MySQL 8 InnoDB clustered database.

Ubuntu 19.10 or above is required.

# Usage

The charm is intended for deploying a cluster and therefore does not deploy on a single unit.

## Cluster deployment

```
juju deploy -n 3 mysql-innodb-cluster
```

The charm is designed to be used with the
[db-router relation](https://github.com/openstack-charmers/charm-interface-mysql-router)
in conjunction with the [MySQL Router charm](https://github.com/openstack-charmers/charm-mysql-router):

```
juju add-relation mysql-innodb-cluster:db-router msyql-router:db-router
```

The charm can be related to existing charms that use the [shared-db relation](https://github.com/openstack/charm-interface-mysql-shared).
However, this relation should be considered deprecated:

```
juju add-relation mysql-innodb-cluster:shared-db keystone:shared-db
```

## Scale out Usage

Nodes can be added to the cluster as Read Only nodes:

```
juju add-unit mysql-innodb-cluster
```

## Known Limitations and Issues

> **Warning**: This charm is in preview state.

The charm is under active development and is not yet production ready. Its
current intended use is for validation of MySQL 8 InnoDB cluster for use with
OpenStack.

# Configuration

The name of the cluster can be customized at deploy time:

```
juju deploy -n 3 mysql-innodb-cluster --config cluster-name myCluster
```

# Contact Information

OpenStack Charmers <openstack-charmers@lists.ubuntu.com>

## Upstream MySQL

  - [Upstream documentation](https://dev.mysql.com/doc/refman/8.0/en/mysql-innodb-cluster-userguide.html)

# Bugs

Please report bugs on [Launchpad](https://bugs.launchpad.net/charm-mysql-innodb-cluster/+filebug).

For general questions please refer to the OpenStack [Charm Guide](https://docs.openstack.org/charm-guide/latest/).
