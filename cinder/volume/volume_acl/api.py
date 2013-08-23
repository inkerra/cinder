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
Handles all requests relating to Volume ACL.
"""


from cinder.db import base
from cinder import exception as exc
from cinder.openstack.common import log as logging
from cinder.volume import api as volume_api
from cinder.volume.volume_acl import access_levels
from cinder.volume.volume_acl import identity


LOG = logging.getLogger(__name__)


class API(base.Base):
    """API for interacting Volume ACL."""

    def __init__(self, db_driver=None):
        self.volume_api = volume_api.API()
        self.identity = identity.API()
        super(API, self).__init__(db_driver)

    def get(self, cxt, volume_permission_id):
        rv = self._volume_permission_get(cxt, volume_permission_id)
        return dict(rv.iteritems())

    def _aggregate_permission(self, perms):
        res = access_levels.NONE
        for perm in perms:
            res = access_levels.aggregate(res, perm.access_permission)
        return res

    def get_access(self, cxt, volume_id):
        vol = self.db.volume_find(cxt, volume_id)
        perm = self._volume_permission_get_by_user(cxt, vol.id)
        if perm:
            return self._aggregate_permission(perm)
        if cxt.is_admin or vol.user_id == cxt.user_id:
            return access_levels.FULL_ACCESS
        return access_levels.NONE

    def _volume_permission_validate_user(self, ctx, subject):
        if subject == 'everyone' or ctx.user_id == subject:
            return subject
        try:
            found = self.identity.get_user(subject)
        except Exception:
            raise exc.VolumePermissionSubjectNotFound(type='user', id=subject)

        if found:
            return found
        raise exc.VolumePermissionSubjectNotFound(type='user', id=subject)

    def _volume_permission_validate_group(self, ctx, subject):
        if subject == 'everyone':
            return subject

        try:
            found = self.identity.get_group(subject)
        except Exception:
            raise exc.VolumePermissionSubjectNotFound(type='group', id=subject)

        if found:
            return found

        raise exc.VolumePermissionSubjectNotFound(type='group', id=subject)

    def _volume_permission_validate_subject(self, ctx, perm_type, subject):
        if perm_type == 'user':
            return self._volume_permission_validate_user(ctx, subject)

        if perm_type == 'group':
            return self._volume_permission_validate_group(ctx, subject)

        raise exc.VolumePermissionSubjectNotFound(type=perm_type, id=subject)

    def _volume_permission_get_by_user(self, cxt, vol_id):
        perms = self.db.volume_permission_get_all_by_volume(cxt, vol_id)

        for_user = filter(
            lambda p: p.type == 'user' and p.entity_id == cxt.user_id, perms)

        if for_user:
            return for_user

        for_everyone = filter(lambda p: p.entity_id == 'everyone', perms)

        if for_everyone:
            return for_everyone

        for_group = filter(
            lambda p: p.type == 'group',
            perms)

        return filter(
            lambda p: self.identity.check_user_in_group(
                cxt.user_id, p.entity_id), for_group)

    def _volume_permission_get(self, cxt, vol_perm_id):
        perm = self.db.volume_permission_get(cxt, vol_perm_id)

        if not perm:
            raise exc.VolumePermissionNotFound(id=vol_perm_id)
        try:
            has_access = self._volume_permission_has_read_perm_access(
                cxt, perm.volume_id)
        except exc.VolumeNotFound:
            raise exc.VolumePermissionNotFound(id=vol_perm_id)

        actual_perms = self._volume_permission_get_by_user(cxt, perm.volume_id)

        if not has_access and \
           not (actual_perms and perm.id in (p.id for p in actual_perms)):
            r = _('wrong access permission level')
            raise exc.NoReadPermissionAccess(reason=r)

        return perm

    def _volume_permission_has_perm_access(self, cxt, vol_id, access_filter):
        if cxt.is_admin:
            return True

        vol = self.db.volume_get(cxt, vol_id)
        if cxt.user_id == vol.user_id:
            return True

        all_perms = self.db.volume_permission_get_all_by_volume(cxt, vol_id)
        perms = filter(access_filter, all_perms)

        for p in filter(lambda p: p.type == 'user', perms):
            if p.entity_id in (cxt.user_id, 'everyone'):
                return True

        for p in filter(lambda p: p.type == 'group', perms):
            if self.identity.check_user_in_group(cxt.user_id, p.entity_id):
                return True
        return False

    def _volume_permission_has_read_perm_access(self, cxt, vol_id):
        return self._volume_permission_has_perm_access(
            cxt, vol_id,
            lambda p: p.access_permission & access_levels.PERMISSION_READ)

    def _volume_permission_has_write_perm_access(self, cxt, vol_id):
        return self._volume_permission_has_perm_access(
            cxt, vol_id,
            lambda p: p.access_permission & access_levels.PERMISSION_WRITE)

    def _get_write_perm_access(self, cxt, vol_id, perm_type, subject):
        if cxt.is_admin:
            return True
        vol = self.db.volume_get(cxt, vol_id)
        # TODO(aguzikova): cross-tenant admin support
        projects_public_for = [vol.project_id]
        if perm_type == 'user' and \
           self.identity.check_user_is_admin(subject, projects_public_for):
            r = _("admin permissions can be changed by admins only")
            raise exc.NoWritePermissionAccess(reason=r)
        if cxt.user_id == vol.user_id:
            return True
        if perm_type == 'user' and subject == vol.user_id:
            r = _("owner permissions can be changed by admins/owner only")
            raise exc.NoWritePermissionAccess(reason=r)

        return self._volume_permission_has_write_perm_access(cxt, vol_id)

    def delete(self, cxt, id):
        """
        Deletes a volume permission in the volume_permissions table.
        """
        p = self.db.volume_permission_get(cxt, id)
        if not p:
            raise exc.VolumePermissionNotFound(id=id)

        if not self._get_write_perm_access(cxt, p['volume_id'], p['type'],
                                           p['entity_id']):
            msg = _("can't delete a permission")
            raise exc.NoWritePermissionAccess(reason=msg)
        self.db.volume_permission_delete(cxt, id)

    def _translate_volume_permission(self, permission):
        return {
            'id': permission['id'],
            'volume_id': permission['volume_id'],
            'type': permission['type'],
            'entity_id': permission['entity_id'],
            'access_permission': permission['access_permission'],
        }

    def _translate_volume_permissions(self, permissions):
        return map(self._translate_volume_permission, permissions)

    def get_all(self, cxt, marker=None, limit=None, sort_key='created_at',
                sort_dir='desc', filters={}):
        if limit is not None:
            try:
                limit = int(limit)
            except ValueError:
                msg = _('limit param must be an integer')
                raise exc.InvalidInput(reason=msg)
            if limit < 0:
                msg = _('limit param must be positive')
                raise exc.InvalidInput(reason=msg)

        if cxt.is_admin:
            results = self.db.volume_permission_get_all(cxt, marker, limit,
                                                        sort_key, sort_dir)
        else:
            results = []
            all_volumes = self.volume_api.get_all(cxt)
            for vol in all_volumes:
                results.extend(self.get_all_by_volume(cxt, vol['id']))
        return self._translate_volume_permissions(results)

    def get_all_by_volume(self, cxt, vol):
        res = []
        vol_id = self.db.volume_find(cxt, vol).id
        if self._volume_permission_has_read_perm_access(cxt, vol_id):
            res = self.db.volume_permission_get_all_by_volume(cxt, vol_id)
        else:
            perm = self._volume_permission_get_by_user(cxt, vol_id)
            if perm:
                res.extend(perm)
        return res

    def create(self, cxt, vol, entity_id=None, permission_type='user',
               access_permission=access_levels.FULL_ACCESS):
        """Creates an entry in the volume_acl_permissions table."""

        vol_id = self.db.volume_find(cxt, vol).id

        if permission_type == 'user' and not entity_id:
            entity_id = cxt.user_id

        entity_id = \
            self._volume_permission_validate_subject(cxt, permission_type,
                                                     entity_id)

        if not self._get_write_perm_access(cxt, vol_id, permission_type,
                                           entity_id):
            msg = _("can't create a permission")
            raise exc.NoWritePermissionAccess(reason=msg)

        LOG.info(_("Generating volume_acl_permission record for volume %s") %
                 vol_id)

        vol_perm = {'volume_id': vol_id,
                    'type': permission_type,
                    'entity_id': entity_id,
                    'access_permission': access_permission,
                    }

        found = self.db.volume_permission_find(cxt, vol_id, entity_id,
                                               permission_type)
        if found:
            vol_perm['id'] = found.id
        try:
            volume_permission = \
                self.db.volume_permission_create_or_update(cxt, vol_perm)
        except Exception:
            LOG.error(_("Failed to create volume_permission record for %s") %
                      vol_id)
            raise
        return volume_permission
