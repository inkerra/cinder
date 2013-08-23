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
Tests for volume acl code.
"""

from datetime import datetime
import json
from xml.dom import minidom

import webob

from cinder import context
from cinder import db
from cinder.openstack.common import log as logging
from cinder.openstack.common import timeutils
from cinder import test
from cinder.tests.api import fakes
from cinder.volume.volume_acl import access_levels
from cinder.volume.volume_acl import API
from cinder.volume.volume_acl import identity


LOG = logging.getLogger(__name__)
volume_acl_api = API()


def fake_wsgi_app():
    # no auth, just let environ['cinder.context'] pass through
    api = fakes.router.APIRouter()
    mapper = fakes.urlmap.URLMap()
    mapper['/v2'] = api
    return mapper


def response(url, method, app, body=None, ctxt=None):
    req = webob.Request.blank(url)
    req.method = method
    if req.method == 'POST':
        if app == 'json':
            req.body = json.dumps(body)
        if app == 'xml':
            req.body = body.encode() if body else ''
    req.headers['Content-Type'] = 'application/%s' % app
    req.headers['Accept'] = 'application/%s' % app
    if ctxt:
        req.environ['cinder.context'] = ctxt
        wsgi_app = fake_wsgi_app()
    else:
        wsgi_app = fakes.wsgi_app()
    return req.get_response(wsgi_app)


def get_response(url, app):
    return response(url, 'GET', app)


def post_response(url, app, body, ctxt=None):
    return response(url, 'POST', app, body=body, ctxt=ctxt)


def delete_response(url, app, ctxt=None):
    return response(url, 'DELETE', app, ctxt=ctxt)


class VolumeACLAPITestCase(test.TestCase):
    """Test Case for Volume ACL API."""

    def setUp(self):
        super(VolumeACLAPITestCase, self).setUp()
        self.ctxt = context.RequestContext(user_id='fake',
                                           project_id='fake')

        def fake_get_subject(self, subject):
            return subject

        def fake_check_user_in_group(self, user_id, group_id):
            return True

        def fake_check_user_is_admin(self, user_id, projects):
            return False

        self.stubs.Set(identity.API, 'get_user',
                       fake_get_subject)
        self.stubs.Set(identity.API, 'get_group',
                       fake_get_subject)
        self.stubs.Set(identity.API, 'check_user_in_group',
                       fake_check_user_in_group)
        self.stubs.Set(identity.API, 'check_user_is_admin',
                       fake_check_user_is_admin)

    def tearDown(self):
        super(VolumeACLAPITestCase, self).tearDown()

    def _create_volume(self, display_name='test_volume',
                       display_description='this is a test volume',
                       status='available',
                       size=1,
                       ctxt=None):
        """Create a volume object."""
        if not ctxt:
            ctxt = self.ctxt
        vol = {}
        vol['size'] = size
        vol['user_id'] = ctxt.user_id
        vol['project_id'] = ctxt.project_id
        vol['status'] = status
        vol['display_name'] = display_name
        vol['display_description'] = display_description
        vol['attach_status'] = status
        return db.volume_create(ctxt, vol)['id']

    def _create_volume_permission(self, volume_id, entity_id, type='user',
                                  access_permission=access_levels.FullAccess,
                                  ctxt=None):
        """Create a volume permission object."""
        if not ctxt:
            ctxt = self.ctxt
        return volume_acl_api.create(ctxt, volume_id, entity_id, type,
                                     access_permission)

    def check_just_created(self, now, perm):
        time = perm['created_at']
        # replace any separator by a space
        time = ' '.join([time[:10], time[11:]])
        created_at_datetime = datetime.strptime(time,
                                                '%Y-%m-%d %H:%M:%S.%f')
        td = now - created_at_datetime  # timedelta
        total_seconds = \
            (td.microseconds +
             (td.seconds + td.days * 24 * 3600) * 10 ** 6) / 10 ** 6
        self.assertTrue(total_seconds < 1)

    def test_show_volume_permission(self):
        volume_id = self._create_volume(size=1)
        now = timeutils.utcnow()
        expected = {'volume_id': volume_id,
                    'entity_id': 'some_user_id',
                    'type': 'user',
                    'access_permission': access_levels.Read,
                    }
        perm = self._create_volume_permission(expected['volume_id'],
                                              expected['entity_id'],
                                              expected['type'],
                                              expected['access_permission'])
        perm_url = '/v2/%s/os-volume-acl/%s' % (self.ctxt.project_id, perm.id)

        res = get_response(perm_url, 'json')

        self.assertEqual(res.status_int, 200)
        res_dict = json.loads(res.body)
        found = res_dict['volume_acl_permission']
        self.check_just_created(now, found)
        self.assertEqual(found['id'], perm['id'])
        for attr in expected:
            self.assertEqual(found[attr], expected[attr])

        db.volume_destroy(context.get_admin_context(), volume_id)
        res = get_response(perm_url, 'json')
        self.assertEqual(res.status_int, 404)

    def test_show_own_volume_permission(self):
        volume_id = self._create_volume(size=1)
        perm_url = '/v2/%s/os-volume-acl/%s' % (self.ctxt.project_id, 1)
        res = get_response(perm_url, 'json')
        self.assertEqual(res.status_int, 404)

        created_perm = self._create_volume_permission(volume_id,
                                                      self.ctxt.user_id)
        now = timeutils.utcnow()

        perm_url = '/v2/%s/os-volume-acl/%s' % (self.ctxt.project_id,
                                                created_perm.id)
        res = get_response(perm_url, 'json')
        self.assertEqual(res.status_int, 200)
        res_dict = json.loads(res.body)
        perm = res_dict['volume_acl_permission']
        self.check_just_created(now, perm)
        expected = {
            'id': created_perm.id,
            'volume_id': volume_id,
            'type': 'user',
            'entity_id': self.ctxt.user_id,
            'access_permission': access_levels.FullAccess,
            'links': [
                {'href': 'http://localhost/v2/fake/volume_acl_permissions/1',
                 'rel': 'self'},
                {'href': 'http://localhost/fake/volume_acl_permissions/1',
                 'rel': u'bookmark'}
            ],
            'created_at': perm['created_at'],
        }
        self.assertEqual(perm, expected)

        db.volume_destroy(context.get_admin_context(), volume_id)
        res = get_response(perm_url, 'json')
        self.assertEqual(res.status_int, 404)

    def test_show_own_volume_permission_xml_content_type(self):
        volume_id = self._create_volume(size=1)
        perm_url = '/v2/%s/os-volume-acl/%s' % (self.ctxt.project_id, 1)
        res = get_response(perm_url, 'xml')
        self.assertEqual(res.status_int, 404)

        created_perm = self._create_volume_permission(volume_id,
                                                      self.ctxt.user_id)
        now = timeutils.utcnow()

        perm_url = '/v2/%s/os-volume-acl/%s' % (self.ctxt.project_id,
                                                created_perm.id)
        res = get_response(perm_url, 'xml')
        self.assertEqual(res.status_int, 200)
        dom = minidom.parseString(res.body)
        perm_xml = dom.getElementsByTagName('volume_acl_permission')[0]
        perm = dict(perm_xml.attributes.items())
        self.assertEqual(int(perm['id']), created_perm.id)
        self.assertEqual(perm['volume_id'], volume_id)
        self.assertEqual(perm['type'], 'user')
        self.assertEqual(perm['entity_id'], self.ctxt.user_id)
        self.assertEqual(int(perm['access_permission']),
                         access_levels.FullAccess)
        self.check_just_created(now, perm)

        db.volume_destroy(context.get_admin_context(), volume_id)
        res = get_response(perm_url, 'xml')
        self.assertEqual(res.status_int, 404)

    def test_show_volume_permission_NotFound(self):
        perm_id = 1234
        perm_url = '/v2/%s/os-volume-acl/%s' % (self.ctxt.project_id, perm_id)
        res = get_response(perm_url, 'json')
        res_dict = json.loads(res.body)

        self.assertEqual(res.status_int, 404)
        self.assertEqual(res_dict['itemNotFound']['code'], 404)
        self.assertEqual(res_dict['itemNotFound']['message'],
                         'Volume Permission 1234 could not be found.')

    def list_volume_permissions_json(self, base_url):
        volumes = [self._create_volume(size=1), self._create_volume(size=1)]
        for vol in volumes:
            self._create_volume_permission(vol, self.ctxt.user_id)

        def get_perms():
            perms_url = base_url % self.ctxt.project_id
            res = get_response(perms_url, 'json')
            self.assertEqual(res.status_int, 200)
            res_dict = json.loads(res.body)
            return res_dict['volume_acl_permissions']

        perms = get_perms()
        length = 2
        self.assertEqual(len(perms), length)
        by_volume = lambda p: p.get('volume_id')
        for (volume, perm) in zip(sorted(volumes),
                                  sorted(perms, key=by_volume)):
            self.assertEqual(perm['volume_id'], volume)
            self.assertEqual(perm['type'], 'user')
            self.assertEqual(perm['entity_id'], self.ctxt.user_id)
            self.assertEqual(perm['access_permission'],
                             access_levels.FullAccess)

        for volume in volumes:
            db.volume_destroy(context.get_admin_context(), volume)
            length -= 1
            perms = get_perms()
            self.assertEqual(len(perms), length)

    def test_list_volume_permissions_json(self):
        self.list_volume_permissions_json('/v2/%s/os-volume-acl')

    def test_list_volume_permissions_detail_json(self):
        self.list_volume_permissions_json('/v2/%s/os-volume-acl/detail')

    def list_volume_permissions_xml(self, base_url):
        volumes = [self._create_volume(size=1), self._create_volume(size=1)]
        for vol in volumes:
            self._create_volume_permission(vol, self.ctxt.user_id)

        def get_perms():
            perms_url = base_url % self.ctxt.project_id
            res = get_response(perms_url, 'xml')
            self.assertEqual(res.status_int, 200)
            dom = minidom.parseString(res.body)
            xml = dom.getElementsByTagName('volume_acl_permissions')[0]
            xml_perms = xml.getElementsByTagName('volume_acl_permission')
            return [dict(elem.attributes.items()) for elem in xml_perms]

        perms = get_perms()
        length = 2
        self.assertEqual(len(perms), length)
        by_volume = lambda p: p.get('volume_id')
        for (volume, perm) in zip(sorted(volumes),
                                  sorted(perms, key=by_volume)):
            self.assertEqual(perm['volume_id'], volume)
            self.assertEqual(perm['type'], 'user')
            self.assertEqual(perm['entity_id'], self.ctxt.user_id)
            self.assertEqual(perm['access_permission'],
                             str(access_levels.FullAccess))

        for volume in volumes:
            db.volume_destroy(context.get_admin_context(), volume)
            length -= 1
            perms = get_perms()
            self.assertEqual(len(perms), length)

    def test_list_volume_permissions_xml(self):
        self.list_volume_permissions_xml('/v2/%s/os-volume-acl')

    def test_list_volume_permissions_detail_xml(self):
        self.list_volume_permissions_xml('/v2/%s/os-volume-acl/detail')

    def test_create_volume_permission_json(self):
        volume_id = self._create_volume(size=1)
        now = timeutils.utcnow()
        body = {'volume_acl_permission':
                {'volume_id': volume_id,
                 'type': 'user',
                 'entity_id': 'some_user_id',
                 'access_permission': access_levels.FullAccess,
                 }
                }
        res = post_response('/v2/fake/os-volume-acl', 'json', body)
        self.assertEqual(res.status_int, 202)
        res_dict = json.loads(res.body)
        LOG.info(res_dict)

        perm = res_dict['volume_acl_permission']
        self.check_just_created(now, perm)
        self.assertTrue('id' in perm)
        self.assertEqual(perm['volume_id'], volume_id)
        self.assertEqual(perm['entity_id'], 'some_user_id')
        self.assertEqual(perm['access_permission'], access_levels.FullAccess)
        self.assertEqual(perm['type'], 'user')
        db.volume_destroy(context.get_admin_context(), volume_id)

    def test_create_volume_permission_xml(self):
        volume_id = self._create_volume(size=1)
        now = timeutils.utcnow()
        vals = {'volume_id': volume_id,
                'type': 'user',
                'entity_id': 'some_user_id',
                'access_permission': str(access_levels.FullAccess),
                }
        body = (('<volume_acl_permission volume_id="%(volume_id)s" '
                 'type="%(type)s" entity_id="%(entity_id)s" '
                 'access_permission="%(access_permission)s" />') % vals)
        res = post_response('/v2/fake/os-volume-acl', 'xml', body)
        self.assertEqual(res.status_int, 202)
        dom = minidom.parseString(res.body)
        perm_xml = dom.getElementsByTagName('volume_acl_permission')[0]
        perm = dict(perm_xml.attributes.items())
        self.check_just_created(now, perm)
        self.assertTrue('id' in perm)
        for key in vals:
            self.assertEquals(perm[key], vals[key])
        db.volume_destroy(context.get_admin_context(), volume_id)

    def test_create_volume_permission_with_no_body(self):
        body = None
        res = post_response('/v2/fake/os-volume-acl', 'json', body)
        res_dict = json.loads(res.body)

        self.assertEqual(res.status_int, 400)
        self.assertEqual(res_dict['badRequest']['code'], 400)
        self.assertEqual(res_dict['badRequest']['message'],
                         'The server could not comply with the request since'
                         ' it is either malformed or otherwise incorrect.')

    def test_create_volume_permission_with_body_KeyError(self):
        body = {'volume_acl_permission': {'wrong key': 'error'}}
        res = post_response('/v2/fake/os-volume-acl', 'json', body)
        res_dict = json.loads(res.body)

        self.assertEqual(res.status_int, 400)
        self.assertEqual(res_dict['badRequest']['code'], 400)
        self.assertEqual(res_dict['badRequest']['message'],
                         'Incorrect request body format')

    def test_create_volume_permission_with_VolumeNotFound(self):
        body = {'volume_acl_permission':
                {'volume_id': 1234,
                 'type': 'user',
                 'entity_id': 'some_user_id',
                 'access_permission': access_levels.FullAccess,
                 }
                }
        res = post_response('/v2/fake/os-volume-acl', 'json', body)
        res_dict = json.loads(res.body)

        self.assertEqual(res.status_int, 404)
        self.assertEqual(res_dict['itemNotFound']['code'], 404)
        self.assertEqual(res_dict['itemNotFound']['message'],
                         'Volume 1234 could not be found.')

    def test_update_volume_permission(self):
        volume_id = self._create_volume(size=1)
        body = {'volume_acl_permission':
                {'volume_id': volume_id,
                 'type': 'user',
                 'entity_id': 'some_user_id',
                 'access_permission': access_levels.FullAccess,
                 }
                }
        res = post_response('/v2/fake/os-volume-acl', 'json', body)
        self.assertEqual(res.status_int, 202)
        res_dict = json.loads(res.body)
        LOG.info(res_dict)

        created_perm = res_dict['volume_acl_permission']

        body['volume_acl_permission']['access_permission'] = \
            access_levels.Write
        res = post_response('/v2/fake/os-volume-acl', 'json', body)
        self.assertEqual(res.status_int, 202)
        res_dict = json.loads(res.body)
        LOG.info(res_dict)

        updated_perm = res_dict['volume_acl_permission']

        self.assertEqual(updated_perm['id'], created_perm['id'])
        expected = body['volume_acl_permission']
        for attr in expected:
            self.assertEqual(updated_perm[attr], expected[attr])

        db.volume_destroy(context.get_admin_context(), volume_id)

    def test_update_owner_volume_permission(self):
        volume_id = self._create_volume(size=1)
        body = {'volume_acl_permission':
                {'volume_id': volume_id,
                 'type': 'user',
                 'entity_id': self.ctxt.user_id,
                 'access_permission': access_levels.PermissionRead,
                 }
                }
        res = post_response('/v2/fake/os-volume-acl', 'json', body)
        self.assertEqual(res.status_int, 202)
        res_dict = json.loads(res.body)
        LOG.info(res_dict)

        updated_perm = res_dict['volume_acl_permission']

        created_perm = db.volume_permission_find(self.ctxt, volume_id,
                                                 self.ctxt.user_id)
        self.assertEqual(updated_perm['id'], created_perm['id'])
        expected = body['volume_acl_permission']
        for attr in expected:
            self.assertEqual(updated_perm[attr], expected[attr])

        db.volume_destroy(context.get_admin_context(), volume_id)

    def test_delete_volume_permission(self):
        volume_id = self._create_volume(size=1)
        perm = db.volume_permission_create_or_update(
            self.ctxt,
            {
                'volume_id': volume_id,
                'type': 'user',
                'entity_id': 'some_user'
            })
        perm_url = '/v2/%s/os-volume-acl/%s' % (self.ctxt.project_id, perm.id)
        res = get_response(perm_url, 'json')

        self.assertEqual(res.status_int, 200)

        res = delete_response('/v2/%s/os-volume-acl/%s' %
                              (self.ctxt.project_id, perm.id), 'json')

        self.assertEqual(res.status_int, 202)

        res = get_response(perm_url, 'json')
        res_dict = json.loads(res.body)

        self.assertEqual(res.status_int, 404)
        self.assertEqual(res_dict['itemNotFound']['code'], 404)
        self.assertEqual(res_dict['itemNotFound']['message'],
                         'Volume Permission %d could not be found.' % perm.id)

    def test_delete_owner_volume_permission(self):
        volume_id = self._create_volume(size=1)
        self._create_volume_permission(volume_id, self.ctxt.user_id)
        perm_id = db.volume_permission_find(self.ctxt, volume_id,
                                            self.ctxt.user_id).id
        res = delete_response('/v2/fake/os-volume-acl/%s' % perm_id, 'json')
        self.assertEqual(res.status_int, 202)

        perm_url = '/v2/%s/os-volume-acl/%s' % (self.ctxt.project_id, perm_id)
        res = get_response(perm_url, 'json')
        res_dict = json.loads(res.body)

        self.assertEqual(res.status_int, 404)
        self.assertEqual(res_dict['itemNotFound']['code'], 404)
        self.assertEqual(res_dict['itemNotFound']['message'],
                         'Volume Permission %d could not be found.' % perm_id)

        db.volume_destroy(context.get_admin_context(), volume_id)

    def test_delete_volume_permission_with_NotFound(self):
        perm_id = 9999
        res = delete_response('/v2/fake/os-volume-acl/%s' % perm_id, 'json',
                              self.ctxt)
        res_dict = json.loads(res.body)

        self.assertEqual(res.status_int, 404)
        self.assertEqual(res_dict['itemNotFound']['code'], 404)
        self.assertEqual(res_dict['itemNotFound']['message'],
                         'Volume Permission 9999 could not be found.')
