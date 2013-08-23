# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (C) 2013 OpenStack Foundation.
# All Rights Reserved.
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

"""
Interface to work with Identity Service.
"""


from oslo.config import cfg

from cinder.db import base
from cinder import exception as exc


config = cfg.CONF
if 'keystone_authtoken' not in config:
    group = cfg.OptGroup('keystone_authtoken')
    config.register_group(group)
    extra_opts = [
        cfg.StrOpt('auth-uri', help='Authentication endpoint'),
        cfg.StrOpt('admin-tenant-name',
                   help='Administrative user\'s tenant name'),
        cfg.StrOpt('admin-user', help='Administrative user\'s id'),
        cfg.StrOpt('admin-password',
                   help='Administrative user\'s password',
                   secret=True),
    ]
    config.register_opts(extra_opts, group=group)


class API(base.Base):
    """Class for work through Keystone Identity Service."""

    def __init__(self, db_driver=None):
        config = cfg.CONF
        if 'keystone_authtoken' not in config:
            extra_opts = [
                cfg.StrOpt('auth-uri', help='Authentication endpoint'),
                cfg.StrOpt('admin-tenant-name',
                           help='Administrative user\'s tenant name'),
                cfg.StrOpt('admin-user', help='Administrative user\'s id'),
                cfg.StrOpt('admin-password',
                           help='Administrative user\'s password',
                           secret=True),
            ]
            config.register_opts(extra_opts, group='keystone_authtoken')

        def _ksc(version):
            auth_uri = '%s/%s/' % (config.keystone_authtoken.auth_uri, version)
            admin_tenant_name = config.keystone_authtoken.admin_tenant_name
            admin_user = config.keystone_authtoken.admin_user
            admin_password = config.keystone_authtoken.admin_password
            if version == 'v3':
                import keystoneclient.v3
                ksc = keystoneclient.v3
            else:
                import keystoneclient.v2_0
                ksc = keystoneclient.v2_0
            ks = ksc.client.Client(username=admin_user,
                                   password=admin_password,
                                   tenant_name=admin_tenant_name,
                                   auth_url=auth_uri)
            return ks
        try:
            self.ksc_v2 = _ksc('v2.0')
            self.ksc_v3 = _ksc('v3')
        except Exception:
            pass
        super(API, self).__init__(db_driver)

    def check_user_in_group(self, user_id, group_id):
        try:
            return self.ksc_v3.users.check_in_group(user_id, group_id)
        except Exception:
            return False

    def check_user_is_admin(self, user_id, projects):
        if user_id == 'everyone':
            return False
        if 'everyone' in projects:
            projects = self.ksc_v2.tenants.list()

            for project in projects:
                roles = self.ksc_v2.roles.roles_for_user(user_id, project)
                admin = filter(lambda r: r.name == 'admin', roles)
                if admin:
                    return True
        return False

    def get_user(self, subject):
        if subject == 'everyone':
            return subject
        found = filter(lambda u: u.name == subject, self.ksc_v2.users.list())
        if len(found) == 1:
            return found[0].id
        try:
            found = self.ksc_v3.users.get(subject)
            return found.id
        except exc.NotFound:
            raise

    def get_group(self, subject):
        if subject == 'everyone':
            return subject
        try:
            found = self.ksc_v3.groups.get(subject)
            return found.id
        except exc.NotFound:
            raise
