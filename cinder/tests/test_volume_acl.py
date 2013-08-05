# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2013 Mirantis Inc.
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
"""Unit Tests for volume acl."""


import datetime

from cinder import context
from cinder import db
from cinder import exception
from cinder.openstack.common import log as logging
from cinder import test
from cinder.volume.volume_acl import api as volume_acl_api


LOG = logging.getLogger(__name__)


class VolumeACLPermissionTestCase(test.TestCase):
    """Test cases for volume ACL code."""
    def setUp(self):
        super(VolumeACLPermissionTestCase, self).setUp()
        self.ctxt = context.RequestContext(user_id='user_id',
                                           project_id='project_id')

    def _create_volume(self, volume_id, status='available',
                       user_id=None, project_id=None, ctxt=None):
        if not ctxt:
            ctxt = self.ctxt
        if user_id is None:
            user_id = ctxt.user_id
        if project_id is None:
            project_id = ctxt.project_id
        vol = {'id': volume_id,
               'updated_at': datetime.datetime(1, 1, 1, 1, 1, 1),
               'user_id': user_id,
               'project_id': project_id,
               'display_name': 'Display Name',
               'display_description': 'Display Description',
               'size': 1,
               'status': status}
        volume = db.volume_create(ctxt, vol)
        return volume

    def test_volume_permission_create_update_delete(self):
        acl_api = volume_acl_api.API()
        volume = self._create_volume('1')
        new_access_permission = 7
        new_user = 'new_user_id'
        new_perm = acl_api.create(self.ctxt, volume.id, new_user,
                                  access_permission=new_access_permission)
        self.assertEquals(new_perm.access_permission, new_access_permission)
        self.assertEquals(new_perm.type, 'user')
        self.assertEquals(new_perm.user_or_group_id, new_user)

        new_owner_permission = 1
        new_owner_perm = acl_api.create(self.ctxt, volume.id,
                                        self.ctxt.user_id,
                                        access_permission=new_owner_permission)
        self.assertEquals(new_owner_perm.user_or_group_id, self.ctxt.user_id)
        nctxt = context.RequestContext(user_id=new_user,
                                       project_id=self.ctxt.project_id)
        self.assertRaises(exception.WrongAccessPermissionLevel,
                          acl_api.create,
                          nctxt, volume.id, self.ctxt.user_id,
                          access_permission=new_owner_permission)
        upd_access_permission = 1
        new_perm = acl_api.create(nctxt, volume.id, new_user,
                                  access_permission=upd_access_permission)
        self.assertEquals(new_perm.access_permission, upd_access_permission)
        self.assertEquals(new_perm.type, 'user')
        self.assertEquals(new_perm.user_or_group_id, new_user)
        perm = acl_api.create(context.get_admin_context(), volume.id,
                              self.ctxt.user_id,
                              access_permission=new_owner_permission)
        self.assertEquals(perm.id, 2)
        self.assertEquals(perm.access_permission, new_owner_permission)
        acl_api.delete(self.ctxt, new_perm.id)
        acl_api.delete(self.ctxt, perm.id)

    def test_volume_permission_create_not_found_volume(self):
        acl_api = volume_acl_api.API()
        self.assertRaises(exception.VolumeNotFound,
                          acl_api.create,
                          self.ctxt, '1', 'new_user_id',
                          access_permission='7')

    def test_volume_permission_get(self):
        acl_api = volume_acl_api.API()
        volume = self._create_volume('1')
        new_access_permission = 7
        new_user = 'new_user_id'
        created_perm = acl_api.create(self.ctxt, volume.id, new_user,
                                      access_permission=new_access_permission)
        new_perm = acl_api.get(self.ctxt, created_perm.id)
        self.assertEquals(created_perm.id, new_perm['id'])
        volume2 = self._create_volume('2')
        acl_api.create(self.ctxt, volume2.id, new_user,
                       access_permission=new_access_permission)
        volume3 = self._create_volume('3', ctxt=context.get_admin_context())
        acl_api.create(context.get_admin_context(), volume3.id,
                       new_user, access_permission=new_access_permission)
        self.assertEquals(volume3.id, '3')
        perms = acl_api.get_all(self.ctxt)
        self.assertEquals(len(perms), 2)
        perms_for_vol1 = acl_api.get_all_by_volume(self.ctxt, volume.id)
        self.assertEquals(len(perms_for_vol1), 1)
        perms_for_vol2 = acl_api.get_all_by_volume(self.ctxt, volume2.id)
        self.assertEquals(len(perms_for_vol2), 1)
        all_perms = acl_api.get_all(context.get_admin_context())
        self.assertEquals(len(all_perms), 3)

        # volume permissions of volume3 (created by admin) is 3
        self.assertRaises(exception.VolumePermissionNotFound,
                          acl_api.get,
                          self.ctxt, '3')
        perm = acl_api.get(context.get_admin_context(), 3)
        self.assertEquals(perm['id'], 3)
