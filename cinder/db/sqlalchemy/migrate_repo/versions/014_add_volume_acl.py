# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 Mirantis Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from cinder.openstack.common import log as logging
from sqlalchemy import Column, MetaData, Boolean, Table
from sqlalchemy import String, Integer, ForeignKey, DateTime, UniqueConstraint

LOG = logging.getLogger(__name__)


def upgrade(migrate_engine):
    """Add volume_acl_permissions table."""
    meta = MetaData()
    meta.bind = migrate_engine

    volumes = Table('volumes', meta, autoload=True)

    volume_acl_permissions = Table(
        'volume_acl_permissions', meta,
        Column('id', Integer, primary_key=True, nullable=False),
        Column('volume_id', String(length=36), ForeignKey('volumes.id'),
               nullable=False),
        Column('type', String(length=10), nullable=False),
        Column('user_or_group_id', String(length=255), nullable=False),
        Column('access_permission', Integer, nullable=False),
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('deleted', Boolean),
        UniqueConstraint('volume_id', 'type', 'user_or_group_id',
                         'deleted', 'deleted_at'),
        mysql_engine='InnoDB'
    )

    try:
        volume_acl_permissions.create()
    except Exception:
        LOG.error(_("Table |%s| is not created!"),
                  repr(volume_acl_permissions))
        raise


def downgrade(migrate_engine):
    """Remove volume_acl_permissions table."""
    meta = MetaData()
    meta.bind = migrate_engine

    volume_acl_permissions = Table('volume_acl_permissions', meta,
                                   autoload=True)
    try:
        volume_acl_permissions.drop()
    except Exception:
        LOG.error(_("volume_acl_permissions table not dropped"))
        raise
