# Copyright (C) 2013 Mirantis Inc.
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
Handles all requests relating to Volume ACL.
"""


from cinder.db import base
from cinder import exception as exc
from cinder.openstack.common import log as logging
from cinder.volume import api as volume_api


LOG = logging.getLogger(__name__)


class API(base.Base):
    """API for interacting Volume ACL."""

    def __init__(self, db_driver=None):
        self.volume_api = volume_api.API()
        super(API, self).__init__(db_driver)

    def get(self, cxt, volume_permission_id):
        rv = self.db.volume_permission_get(cxt, volume_permission_id)
        return dict(rv.iteritems())

    def _get_write_perm_access(self, cxt, vol_id, perm_type, user_or_group_id):
        #if perm_type == 'user' \
        #   and self.db.check_user_is_admin(cxt, user_or_group_id):
        #    r = _("Admin's permissions can't be modified")
        #    raise exc.NoWritePermissionAccess(reason=r)
        vol = self.db.volume_get(cxt, vol_id)
        if cxt.is_admin or cxt.user_id == vol.user_id:
            return True
        if perm_type == 'user' and user_or_group_id == vol.user_id:
            r = _("owner's permissions can be changed by admins only")
            raise exc.NoWritePermissionAccess(reason=r)

        return self.db.volume_permission_has_write_perm_access(cxt, vol_id)

    def delete(self, cxt, id):
        """
        Deletes a volume permission in the volume_permissions table.
        """
        p = self.db.volume_permission_get(cxt, id)
        write_perm_access = self._get_write_perm_access(cxt, p['volume_id'],
                                                        p['type'],
                                                        p['user_or_group_id'])
        volume_api.check_policy(cxt, 'delete_volume_permission',
                                {'write_permission_access': write_perm_access})
        self.db.volume_permission_delete(cxt, id)

    def get_all(self, cxt, filters={}):
        return self.db.volume_permission_get_all(cxt)

    def get_all_by_volume(self, cxt, volume_id):
        return self.db.volume_permission_get_all_by_volume(cxt, volume_id)

    def create(self, cxt, vol, user_or_group_id, perm_type='user',
               access_permission=7):
        """Creates an entry in the volume_acl_permissions table."""

        vol_id = self.db.volume_find(cxt, vol).id

        if perm_type == 'user' and not user_or_group_id:
            user_or_group_id = cxt.user_id

        user_or_group_id = \
            self.db.volume_permission_validate_subject(cxt, perm_type,
                                                       user_or_group_id)

        write_perm_access = self._get_write_perm_access(cxt, vol_id, perm_type,
                                                        user_or_group_id)
        volume_api.check_policy(cxt, 'create_volume_permission',
                                {'write_permission_access': write_perm_access})

        LOG.info("Generating volume_acl_permission record for volume %s" %
                 vol_id)

        volume_permission_rec = {'volume_id': vol_id,
                                 'type': perm_type,
                                 'user_or_group_id': user_or_group_id,
                                 'access_permission': access_permission,
                                 }

        try:
            volume_permission = \
                self.db.volume_permission_create(cxt, volume_permission_rec)
        except Exception:
            LOG.error(_("Failed to create volume_permission record for %s") %
                      vol_id)
            raise
        return volume_permission
