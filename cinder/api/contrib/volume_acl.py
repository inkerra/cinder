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

import webob
from webob import exc
from xml.dom import minidom

from cinder.api import common
from cinder.api import extensions
from cinder.api.openstack import wsgi
from cinder.api.views import volume_acl as volume_acl_view
from cinder.api import xmlutil

from cinder import exception
from cinder.openstack.common import log as logging
from cinder.volume import volume_acl as volume_aclAPI

LOG = logging.getLogger(__name__)


def make_volume_permission(elem):
    elem.set('id')
    elem.set('volume_id')
    elem.set('type')
    elem.set('entity_id')
    elem.set('access_permission')
    elem.set('created_at')


class VolumePermissionTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('volume_acl_permission',
                                       selector='volume_acl_permission')
        make_volume_permission(root)
        alias = Volume_acl.alias
        namespace = Volume_acl.namespace
        return xmlutil.MasterTemplate(root, 1, nsmap={alias: namespace})


class VolumePermissionsTemplate(xmlutil.TemplateBuilder):
    def construct(self):
        root = xmlutil.TemplateElement('volume_acl_permissions')
        elem = xmlutil.SubTemplateElement(root, 'volume_acl_permission',
                                          selector='volume_acl_permissions')
        make_volume_permission(elem)
        alias = Volume_acl.alias
        namespace = Volume_acl.namespace
        return xmlutil.MasterTemplate(root, 1, nsmap={alias: namespace})


class CreateDeserializer(wsgi.MetadataXMLDeserializer):
    def default(self, string):
        dom = minidom.parseString(string)
        volume_permission = self._extract_volume_permission(dom)
        return {'body': {'volume_acl_permission': volume_permission}}

    def _extract_volume_permission(self, node):
        volume_permission = {}
        volume_permission_node = \
            self.find_first_child_named(node, 'volume_acl_permission')

        attributes = ['id', 'volume_id', 'type', 'entity_id',
                      'access_permission']

        for attr in attributes:
            if volume_permission_node.getAttribute(attr):
                volume_permission[attr] = \
                    volume_permission_node.getAttribute(attr)
        return volume_permission


class VolumeACLController(wsgi.Controller):
    """The Volume ACL API controller for the Openstack API."""

    _view_builder_class = volume_acl_view.ViewBuilder

    def __init__(self):
        self.volume_acl_api = volume_aclAPI.API()
        super(VolumeACLController, self).__init__()

    @wsgi.serializers(xml=VolumePermissionTemplate)
    def show(self, req, id):
        """Return data about active volume_permissions."""
        context = req.environ['cinder.context']

        if 'volume_id' in req.params:
            volume_id = req.params['volume_id']
            access = self.volume_acl_api.get_access(context, volume_id)
            return self._view_builder.access(req, access)

        try:
            volume_permission = \
                self.volume_acl_api.get(context, volume_permission_id=id)
        except exception.VolumePermissionNotFound as error:
            raise exc.HTTPNotFound(explanation=unicode(error))

        return self._view_builder.detail(req, volume_permission)

    @wsgi.serializers(xml=VolumePermissionsTemplate)
    def index(self, req):
        """Returns a summary list of volume_permissions"""
        return self._get_volume_permissions(req, is_detail=False)

    @wsgi.serializers(xml=VolumePermissionsTemplate)
    def detail(self, req, volume_id=None):
        """Returns a detailed list of volume_permissions."""
        return self._get_volume_permissions(req, is_detail=True)

    def _get_volume_permissions(self, req, is_detail):
        """
        Returns a list of volume_permissions, transformed through view builder.
        """
        context = req.environ['cinder.context']
        if 'volume_id' in req.params:
            volume_id = req.params['volume_id']
            LOG.debug(_('Listing volume permissions for volume: %s'),
                      volume_id)
            volume_permissions = \
                self.volume_acl_api.get_all_by_volume(context, volume_id)
        else:
            LOG.debug(_('Listing volume permissions'))
            volume_permissions = self.volume_acl_api.get_all(context)
        limited_list = common.limited(volume_permissions, req)

        if is_detail:
            volume_permissions = self._view_builder.detail_list(req,
                                                                limited_list)
        else:
            volume_permissions = self._view_builder.summary_list(req,
                                                                 limited_list)

        return volume_permissions

    @wsgi.response(202)
    @wsgi.serializers(xml=VolumePermissionTemplate)
    @wsgi.deserializers(xml=CreateDeserializer)
    def create(self, req, body):
        """Create a new volume permission."""
        LOG.debug(_('Creating new volume permission %s'), body)
        if not self.is_valid_body(body, 'volume_acl_permission'):
            raise exc.HTTPBadRequest()

        context = req.environ['cinder.context']

        try:
            volume_permission = body['volume_acl_permission']
            volume_id = volume_permission['volume_id']
        except KeyError:
            msg = _("Incorrect request body format")
            raise exc.HTTPBadRequest(explanation=msg)

        permission_type = volume_permission['type']
        entity_id = volume_permission['entity_id']
        access_permission = volume_permission['access_permission']

        LOG.audit(_("Creating volume_permission of volume %s"),
                  volume_id,
                  context=context)

        try:
            kwargs = {}
            if permission_type:
                kwargs['permission_type'] = permission_type
            if access_permission:
                kwargs['access_permission'] = access_permission
            if entity_id:
                kwargs['entity_id'] = entity_id
            new_volume_permission = \
                self.volume_acl_api.create(context, volume_id, **kwargs)
        except exception.InvalidVolume as error:
            raise exc.HTTPBadRequest(explanation=unicode(error))
        except exception.VolumeNotFound as error:
            raise exc.HTTPNotFound(explanation=unicode(error))

        new_volume_permission_dict = dict(new_volume_permission.iteritems())
        volume_permission = \
            self._view_builder.create(req, new_volume_permission_dict)
        return volume_permission

    def delete(self, req, id):
        """Delete a volume_permission."""
        context = req.environ['cinder.context']

        LOG.audit(_("Delete volume_permission with id: %s"), id,
                  context=context)

        try:
            self.volume_acl_api.delete(context, id)
        except exception.VolumePermissionNotFound as error:
            raise exc.HTTPNotFound(explanation=unicode(error))
        return webob.Response(status_int=202)


class Volume_acl(extensions.ExtensionDescriptor):
    """Volume ACL management support"""

    name = "VolumeACLPermission"
    alias = "os-volume-acl"
    namespace = "http://docs.openstack.org/volume/ext/" + \
                "volume-acl/api/v1.1"
    updated = "2013-07-15T00:00:00+00:00"

    def get_resources(self):
        resources = []

        col_actions = {
            'detail': 'GET',
        }
        res = extensions.ResourceExtension(Volume_acl.alias,
                                           VolumeACLController(),
                                           collection_actions=col_actions,
                                           )
        resources.append(res)
        return resources
