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

"""Tests for volume acl permissions table."""

from cinder import context
from cinder import db
from cinder import test


class VolumeACLPermissionsTableTestCase(test.TestCase):
    """Test case for volume acl permissions model."""

    def setUp(self):
        super(VolumeACLPermissionsTableTestCase, self).setUp()
        self.ctxt = context.RequestContext(user_id='user_id',
                                           project_id='project_id')

    def _create_volume(self, display_name='test_volume',
                       display_description='this is a test volume',
                       status='available', size=1):
        """Create a volume object."""
        vol = {
            'size': size,
            'user_id': self.ctxt.user_id,
            'project_id': self.ctxt.project_id,
            'status': status,
            'display_name': display_name,
            'display_description': display_description,
            'attach_status': 'detached',
        }
        return db.volume_create(self.ctxt, vol)['id']

    def _create_volume_permission(self, volume_id, entity_id,
                                  perm_type='user', access_permission=15):
        """Create a volume permission object."""
        volume_permission = {
            'volume_id': volume_id,
            'type': perm_type,
            'entity_id': entity_id,
            'access_permission': access_permission,
        }
        return db.volume_permission_create_or_update(self.ctxt,
                                                     volume_permission)['id']

    def _volume_permission_detail(self, permission):
        return {
            'id': permission['id'],
            'volume_id': permission['volume_id'],
            'type': permission['type'],
            'entity_id': permission['entity_id'],
            'access_permission': permission['access_permission'],
            'deleted': permission['deleted'],
            'deleted_at': permission['deleted_at'],
            'created_at': permission['created_at'],
            'updated_at': permission['updated_at'],
        }

    def test_volume_permission_create(self):
        volume_id = self._create_volume(size=1)
        self._create_volume_permission(volume_id=volume_id,
                                       entity_id=self.ctxt.user_id,
                                       access_permission=8)

    def test_volume_permission_update(self):
        volume_id = self._create_volume(size=1)
        perm_id = self._create_volume_permission(
            volume_id=volume_id, entity_id=self.ctxt.user_id,
            access_permission=8)
        volume_permission = {
            'id': perm_id,
            'volume_id': volume_id,
            'type': 'user',
            'entity_id': 'new_user',
            'access_permission': 1,
        }
        updated = db.volume_permission_create_or_update(self.ctxt,
                                                        volume_permission)
        for key in volume_permission:
            self.assertTrue(updated[key], volume_permission[key])

    def test_volume_permission_get(self):
        volume_id1 = self._create_volume(size=1)
        perm_id = self._create_volume_permission(volume_id1, self.ctxt.user_id)
        vol_perm = db.volume_permission_get(self.ctxt, perm_id)
        self.assertEquals(vol_perm.volume_id, volume_id1,
                          "Unexpected volume_id")

    def test_volume_permission_get_by_another_user(self):
        volume_id1 = self._create_volume(size=1)
        perm_id = self._create_volume_permission(volume_id1, self.ctxt.user_id)
        vol_perm = db.volume_permission_get(self.ctxt, perm_id)
        nctxt = context.RequestContext(user_id='new_user_id',
                                       project_id='new_project_id')

        vol_perm = db.volume_permission_get(nctxt, perm_id)
        self.assertEquals(vol_perm.volume_id, volume_id1,
                          "Unexpected volume_id")

    def test_volume_permission_find(self):
        volume_id = self._create_volume(size=1)
        perm_id = self._create_volume_permission(volume_id, self.ctxt.user_id)
        found = db.volume_permission_find(self.ctxt, volume_id,
                                          self.ctxt.user_id, 'user')
        perm = db.volume_permission_get(self.ctxt, perm_id)
        self.assertEquals(self._volume_permission_detail(perm),
                          self._volume_permission_detail(found))

    def test_volume_permission_get_all(self):
        volumes = [self._create_volume(size=1), self._create_volume(size=1)]
        for vol in volumes:
            self._create_volume_permission(vol, self.ctxt.user_id)
        perms = db.volume_permission_get_all(self.ctxt, None, None,
                                             'created_at', 'desc')
        self.assertEquals(len(perms), len(volumes),
                          "Unexpected number of volume permission records")

    def test_volume_permission_get_all_by_volume(self):
        volume_id = self._create_volume(size=1)
        self._create_volume_permission(volume_id, self.ctxt.user_id)
        self._create_volume_permission(volume_id=volume_id,
                                       entity_id='user_id2',
                                       access_permission=3)
        volume_id2 = self._create_volume(size=1)
        self._create_volume_permission(volume_id=volume_id2,
                                       entity_id='user_id2',
                                       access_permission=4)
        perms = db.volume_permission_get_all_by_volume(self.ctxt, volume_id)
        self.assertEquals(len(perms), 2,
                          "Unexpected number of volume permission records")

    def test_volume_permission_delete(self):
        vol1 = self._create_volume(size=1)
        self._create_volume_permission(vol1, self.ctxt.user_id)
        vol2 = self._create_volume(size=1)
        self._create_volume_permission(vol2, self.ctxt.user_id)
        perms = db.volume_permission_get_all(self.ctxt, None, None,
                                             'created_at', 'desc')
        db.volume_permission_delete(self.ctxt, perms[0]['id'])
        perms = db.volume_permission_get_all(self.ctxt, None, None,
                                             'created_at', 'desc')
        self.assertEquals(len(perms), 1,
                          "Unexpected number of volume permission records")

    def test_volume_permission_delete_by_another_user(self):
        vol1 = self._create_volume(size=1)
        self._create_volume_permission(vol1, self.ctxt.user_id)
        nctxt = context.RequestContext(user_id='new_user_id',
                                       project_id='new_project_id')
        perms = db.volume_permission_get_all(self.ctxt, None, None,
                                             'created_at', 'desc')
        db.volume_permission_delete(nctxt, perms[0]['id'])
        perms = db.volume_permission_get_all(self.ctxt,
                                             None, None, 'created_at', 'desc')
        self.assertEquals(len(perms), 0,
                          "Unexpected number of volume permission records")
