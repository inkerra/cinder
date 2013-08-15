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

"""Tests for volume acl permissions table."""

from cinder import context
from cinder import db
from cinder import exception
from cinder.openstack.common import log as logging
from cinder import test


LOG = logging.getLogger(__name__)


class VolumeACLPermissionsTableTestCase(test.TestCase):
    """Test case for volume acl permissions model."""

    def setUp(self):
        super(VolumeACLPermissionsTableTestCase, self).setUp()
        self.ctxt = context.RequestContext(user_id='user_id',
                                           project_id='project_id')

    def tearDown(self):
        super(VolumeACLPermissionsTableTestCase, self).tearDown()

    def _create_volume(self,
                       display_name='test_volume',
                       display_description='this is a test volume',
                       status='available',
                       size=1):
        """Create a volume object."""
        vol = {}
        vol['size'] = size
        vol['user_id'] = self.ctxt.user_id
        vol['project_id'] = self.ctxt.project_id
        vol['status'] = status
        vol['display_name'] = display_name
        vol['display_description'] = display_description
        vol['attach_status'] = 'detached'
        return db.volume_create(self.ctxt, vol)['id']

    def _create_volume_permission(self, volume_id, user_or_group_id,
                                  perm_type='user', access_permission=7):
        """Create a volume permission object."""
        volume_permission = {}
        volume_permission['volume_id'] = volume_id
        volume_permission['type'] = perm_type
        volume_permission['user_or_group_id'] = user_or_group_id
        volume_permission['access_permission'] = access_permission
        return db.volume_permission_create(self.ctxt, volume_permission)['id']

    def test_volume_permission_create(self):
        volume_id = self._create_volume(size=1)
        self._create_volume_permission(volume_id=volume_id,
                                       user_or_group_id=self.ctxt.user_id,
                                       access_permission=4)

    def test_volume_permission_get(self):
        volume_id1 = self._create_volume(size=1)
        perm_id = self._create_volume_permission(volume_id1, self.ctxt.user_id)
        vol_perm = db.volume_permission_get(self.ctxt, perm_id)
        self.assertEquals(vol_perm.volume_id, volume_id1,
                          "Unexpected volume_id")

        nctxt = context.RequestContext(user_id='new_user_id',
                                       project_id='new_project_id')
        self.assertRaises(exception.VolumePermissionNotFound,
                          db.volume_permission_get, nctxt, perm_id)

        vol_perm = db.volume_permission_get(nctxt.elevated(), perm_id)
        self.assertEquals(vol_perm.volume_id, volume_id1,
                          "Unexpected volume_id")

    def test_volume_permission_get_existent(self):
        volume_id = self._create_volume(size=1)
        perm_id = self._create_volume_permission(volume_id, self.ctxt.user_id)
        found = db.volume_permission_get_existent(self.ctxt, volume_id,
                                                  self.ctxt.user_id, 'user')
        perm = db.volume_permission_get(self.ctxt, perm_id)
        self.assertEquals(db.volume_permission_detail(perm),
                          db.volume_permission_detail(found))

    def test_volume_permission_get_by_user(self):
        volume_id = self._create_volume(size=1)
        perm_id = self._create_volume_permission(volume_id, self.ctxt.user_id)
        perm = db.volume_permission_get_by_user(self.ctxt, volume_id)
        self.assertEquals(perm.access_permission, 7)
        new_access_perm = 4
        perm_id = self._create_volume_permission(volume_id=volume_id,
                                                 user_or_group_id=
                                                 self.ctxt.user_id,
                                                 access_permission=
                                                 new_access_perm)
        self.assertEquals(perm_id, perm.id)
        perm2 = db.volume_permission_get(self.ctxt, perm_id)
        self.assertEquals(perm2.access_permission, new_access_perm)

    def test_volume_permission_get_all(self):
        volumes = [self._create_volume(size=1), self._create_volume(size=1)]
        for vol in volumes:
            self._create_volume_permission(vol, self.ctxt.user_id)
        perms = db.volume_permission_get_all(self.ctxt)
        self.assertEquals(len(perms), len(volumes),
                          "Unexpected number of volume permission records")

    def test_volume_permission_get_all_by_volume(self):
        volume_id = self._create_volume(size=1)
        self._create_volume_permission(volume_id, self.ctxt.user_id)
        self._create_volume_permission(volume_id=volume_id,
                                       user_or_group_id='user_id2',
                                       access_permission=3)
        volume_id2 = self._create_volume(size=1)
        self._create_volume_permission(volume_id, self.ctxt.user_id)
        self._create_volume_permission(volume_id=volume_id2,
                                       user_or_group_id='user_id2',
                                       access_permission=4)
        perms = db.volume_permission_get_all_by_volume(self.ctxt, volume_id)
        self.assertEquals(len(perms), 2,
                          "Unexpected number of volume permission records")

    def test_volume_permission_delete(self):
        vol1 = self._create_volume(size=1)
        self._create_volume_permission(vol1, self.ctxt.user_id)
        vol2 = self._create_volume(size=1)
        self._create_volume_permission(vol2, self.ctxt.user_id)
        perms = db.volume_permission_get_all(self.ctxt)
        self.assertEquals(len(perms), 2,
                          "Unexpected number of transfer records")
        db.volume_permission_delete(self.ctxt, perms[0]['id'])
        perms = db.volume_permission_get_all(self.ctxt)
        self.assertEquals(len(perms), 1,
                          "Unexpected number of transfer records")
        nctxt = context.RequestContext(user_id='new_user_id',
                                       project_id='new_project_id')
        self.assertRaises(exception.VolumePermissionNotFound,
                          db.volume_permission_delete, nctxt, perms[0]['id'])
        db.volume_permission_delete(nctxt.elevated(), perms[0]['id'])
        perms = db.volume_permission_get_all(context.get_admin_context())
        self.assertEquals(len(perms), 0,
                          "Unexpected number of volume permission records")
