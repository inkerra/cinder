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

from cinder.api import common
from cinder.openstack.common import log as logging


LOG = logging.getLogger(__name__)


class ViewBuilder(common.ViewBuilder):
    """Model volume_acl_permission API responses as a python dictionary."""

    _collection_name = "volume_acl_permissions"

    def __init__(self):
        """Initialize view builder."""
        super(ViewBuilder, self).__init__()

    def summary_list(self, request, volume_acl_permissions):
        """Show a list of volume permissions without many details."""
        return self._list_view(self.summary, request, volume_acl_permissions)

    def detail_list(self, request, volume_acl_permissions):
        """Detailed view of a list of volume_acl_permissions ."""
        return self._list_view(self.detail, request, volume_acl_permissions)

    def summary(self, request, volume_acl_permission):
        """Generic, non-detailed view of a volume_acl_permission."""
        return {
            'volume_acl_permission': {
                'id': volume_acl_permission.get('id'),
                'volume_id': volume_acl_permission.get('volume_id'),
                'type': volume_acl_permission.get('type'),
                'user_or_group_id':
                volume_acl_permission.get('user_or_group_id'),
                'access_permission':
                volume_acl_permission.get('access_permission'),
                'links': self._get_links(request, volume_acl_permission['id']),
            },
        }

    def detail(self, request, volume_acl_permission):
        """Detailed view of a single volume permission."""
        return {
            'volume_acl_permission': {
                'id': volume_acl_permission.get('id'),
                'created_at': volume_acl_permission.get('created_at'),
                'volume_id': volume_acl_permission.get('volume_id'),
                'type': volume_acl_permission.get('type'),
                'user_or_group_id':
                volume_acl_permission.get('user_or_group_id'),
                'access_permission':
                volume_acl_permission.get('access_permission'),
                'links': self._get_links(request, volume_acl_permission['id']),
            }
        }

    def access(self, request, access):
        """View of volume access permission."""
        return {
            'volume_acl_permission': {
                'id': None,
                'created_at': None,
                'volume_id': None,
                'type': None,
                'user_or_group_id': None,
                'access_permission': access,
                'links': None,
            }
        }

    def create(self, request, volume_acl_permission):
        """Detailed view of a single volume permission when created."""
        return {
            'volume_acl_permission': {
                'id': volume_acl_permission.get('id'),
                'created_at': volume_acl_permission.get('created_at'),
                'volume_id': volume_acl_permission.get('volume_id'),
                'type': volume_acl_permission.get('type'),
                'user_or_group_id':
                volume_acl_permission.get('user_or_group_id'),
                'access_permission':
                volume_acl_permission.get('access_permission'),
                'links': self._get_links(request, volume_acl_permission['id'])
            }
        }

    def _list_view(self, func, request, volume_acl_permissions):
        """Provide a view for a list of volume permissions."""
        vol_perms_list = [func(request, p)['volume_acl_permission']
                          for p in volume_acl_permissions]
        vol_perms_links = self._get_collection_links(request,
                                                     volume_acl_permissions,
                                                     self._collection_name)
        vol_perms_dict = dict(volume_acl_permissions=vol_perms_list)

        if vol_perms_links:
            vol_perms_dict['volume_acl_permissions_links'] = vol_perms_links

        return vol_perms_dict
