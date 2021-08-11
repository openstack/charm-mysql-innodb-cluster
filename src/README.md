# Overview

The mysql-innodb-cluster charm deploys a [MySQL 8][upstream-mysql8] InnoDB
clustered database (i.e. MySQL InnoDB Cluster). It is used in conjunction with
the [mysql-router][mysql-router-charm] subordinate charm.

> **Important**: The eoan series is the first series supported by the
  mysql-innodb-cluster and mysql-router charms. These charms replace the
  [percona-cluster][percona-cluster-charm] charm starting with the focal
  series.

# Usage

## Configuration

See file `config.yaml` of the built charm (or see the charm in the [Charm
Store][mysql-innodb-cluster-charm]) for the full list of configuration options,
along with their descriptions and default values. See the [Juju
documentation][juju-docs-config-apps] for details on configuring applications.

## Deployment

MySQL 8 is natively HA and requires at least three database units, which are
often containerised. To deploy a three-node cluster to new containers on
machines '0', '1', and '2':

    juju deploy -n 3 --to lxd:0,lxd:1,lxd:2 mysql-innodb-cluster

A cloud application is joined to the database via an instance of mysql-router.
For a pre-existing keystone application:

    juju deploy mysql-router keystone-mysql-router
    juju add-relation keystone-mysql-router:db-router mysql-innodb-cluster:db-router
    juju add-relation keystone-mysql-router:shared-db keystone:shared-db

See [Infrastructure high availability][cdg-app-ha-mysql8] in the [OpenStack
Charms Deployment Guide][cdg] for more deploy information.

## Root password

Passwords are automatically generated and stored by the application leader.

The root password required to use the `mysql` or `mysqlsh` utilities locally on the
units can be retrieved using the following command:

    juju run --unit mysql-innodb-cluster/leader leader-get mysql.passwd

## TLS

TLS communication between MySQL InnoDB Cluster and its cloud clients is
supported out of the box via a self-signed CA certificate bundled within MySQL
itself.

A better option is to use a certificate signed by a Vault-based CA. This can be
done once Vault has been initialised and has a root CA:

    juju add-relation mysql-innodb-cluster:certificates vault:certificates

See the [vault][vault-charm-readme] charm README for more information.

## Adding a unit on a new subnet

If a new unit is added after the cluster has already formed and the new unit
is on different subnet to any of the existing units then the following actions
are needed to add the unit to the cluster:

    juju run-action mysql-innodb-cluster/leader update-unit-acls
    juju run-action mysql-innodb-cluster/leader add-instance address=<address of new unit>

## Actions

This section lists Juju [actions][juju-docs-actions] supported by the charm.
Actions allow specific operations to be performed on a per-unit basis. To
display action descriptions run `juju actions --schema mysql-innodb-cluster`.
If the charm is not deployed then see file `actions.yaml`.

* `add-instance`
* `cluster-rescan`
* `cluster-status`
* `mysqldump`
* `reboot-cluster-from-complete-outage`
* `rejoin-instance`
* `remove-instance`
* `restore-mysqldump`
* `set-cluster-option`
* `update-unit-acls`

# Documentation

The OpenStack Charms project maintains two documentation guides:

* [OpenStack Charm Guide][cg]: for project information, including development
  and support notes
* [OpenStack Charms Deployment Guide][cdg]: for charm usage information

# Bugs

Please report bugs on [Launchpad][lp-bugs-charm-mysql-innodb-cluster].

<!-- LINKS -->

[cg]: https://docs.openstack.org/charm-guide
[cdg]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide
[lp-bugs-charm-mysql-innodb-cluster]: https://bugs.launchpad.net/charm-mysql-innodb-cluster/+filebug
[juju-docs-actions]: https://jaas.ai/docs/actions
[percona-cluster-charm]: https://jaas.ai/percona-cluster
[mysql-innodb-cluster-charm]: https://jaas.ai/mysql-innodb-cluster
[mysql-router-charm]: https://jaas.ai/mysql-router
[vault-charm-readme]: https://opendev.org/openstack/charm-vault/src/branch/master/src/README.md
[upstream-mysql8]: https://dev.mysql.com/doc/refman/8.0/en/mysql-innodb-cluster-userguide.html
[cdg-app-ha-mysql8]: https://docs.openstack.org/project-deploy-guide/charm-deployment-guide/latest/app-ha.html#mysql-8
[juju-docs-config-apps]: https://juju.is/docs/configuring-applications
