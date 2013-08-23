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
        NoPermission, Read, Write, PermissionRead, PermissionWrite, \
            ReadAndPermissionRead, WriteAndPermissionRead, FullAccess, \
            ReadAndPermissionWrite = range(9)
        res = NoPermission
        for perm in perms:
            addendum = perm.access_permission
            if addendum == FullAccess:
                return addendum
            if res == addendum:
                continue
            maps = {
                Read + Write: Write,
                Read + PermissionRead: ReadAndPermissionRead,
                Read + PermissionWrite: ReadAndPermissionWrite,
                Read + ReadAndPermissionRead: ReadAndPermissionRead,
                Read + WriteAndPermissionRead: WriteAndPermissionRead,
                Write + PermissionRead: WriteAndPermissionRead,
                Write + PermissionWrite: FullAccess,
                Write + ReadAndPermissionRead: WriteAndPermissionRead,
                Write + WriteAndPermissionRead: WriteAndPermissionRead,
                PermissionRead + PermissionWrite: PermissionWrite,
                PermissionRead + ReadAndPermissionRead: ReadAndPermissionRead,
                PermissionRead + WriteAndPermissionRead:
                WriteAndPermissionRead,
                PermissionWrite + ReadAndPermissionRead:
                ReadAndPermissionWrite,
                PermissionWrite + WriteAndPermissionRead: FullAccess,
                ReadAndPermissionRead + WriteAndPermissionRead:
                WriteAndPermissionRead,
            }
            res = maps.get(res + addendum, res)
            if res == FullAccess:
                return res

        return res

    def get_access(self, cxt, volume_id):
        vol = self.db.volume_find(cxt, volume_id)
        perm = self._volume_permission_get_by_user(cxt, vol.id)
        if perm:
            return self._aggregate_permission(perm)
        if cxt.is_admin or vol.user_id == cxt.user_id:
            return 7
        return 0

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
            lambda p: p.type == 'user' and p.user_or_group_id == cxt.user_id,
            perms)

        if for_user:
            return for_user

        for_everyone = filter(
            lambda p: p.user_or_group_id == 'everyone',
            perms)

        if for_everyone:
            return for_everyone

        for_group = filter(
            lambda p: p.type == 'group',
            perms)

        return filter(
            lambda p: self.identity.check_user_in_group(
                cxt.user_id, p.user_or_group_id), for_group)

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
            if p.user_or_group_id in (cxt.user_id, 'everyone'):
                return True

        for p in filter(lambda p: p.type == 'group', perms):
            if self.identity.check_user_in_group(cxt.user_id,
                                                 p.user_or_group_id):
                return True
        return False

    def _volume_permission_has_read_perm_access(self, cxt, vol_id):
        return self._volume_permission_has_perm_access(
            cxt, vol_id, lambda p: p.access_permission >= 3)

    def _volume_permission_has_write_perm_access(self, cxt, vol_id):
        return self._volume_permission_has_perm_access(
            cxt, vol_id, lambda p: p.access_permission in (4, 7))

    def _get_write_perm_access(self, cxt, vol_id, perm_type, subject):
        if cxt.is_admin:
            return True
        vol = self.db.volume_get(cxt, vol_id)
        #TODO(aguzikova): cross-tenant admin support
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

        write_perm_access = self._get_write_perm_access(cxt, p['volume_id'],
                                                        p['type'],
                                                        p['user_or_group_id'])
        volume_api.check_policy(cxt, 'delete_volume_permission',
                                {'write_permission_access': write_perm_access})
        self.db.volume_permission_delete(cxt, id)

    def _translate_volume_permission(self, permission):
        r = {}
        r['id'] = permission['id']
        r['volume_id'] = permission['volume_id']
        r['type'] = permission['type']
        r['user_or_group_id'] = permission['user_or_group_id']
        r['access_permission'] = permission['access_permission']
        return r

    def _translate_volume_permissions(self, permissions):
        return map(self._translate_volume_permission, permissions)

    def get_all(self, cxt, marker=None, limit=None, sort_key='created_at',
                sort_dir='desc', filters={}):
        try:
            if limit is not None:
                limit = int(limit)
                if limit < 0:
                    msg = _('limit param must be positive')
                    raise exc.InvalidInput(reason=msg)
        except ValueError:
            msg = _('limit param must be an integer')
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

    def create(self, cxt, vol, user_or_group_id, perm_type='user',
               access_permission=7):
        """Creates an entry in the volume_acl_permissions table."""

        vol_id = self.db.volume_find(cxt, vol).id

        if perm_type == 'user' and not user_or_group_id:
            user_or_group_id = cxt.user_id

        user_or_group_id = \
            self._volume_permission_validate_subject(cxt, perm_type,
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

        found = self.db.volume_permission_find(cxt, vol_id, user_or_group_id,
                                               perm_type)
        if found:
            volume_permission_rec['id'] = found.id
        try:
            volume_permission = \
                self.db.volume_permission_create(cxt, volume_permission_rec)
        except Exception:
            LOG.error(_("Failed to create volume_permission record for %s") %
                      vol_id)
            raise
        return volume_permission
