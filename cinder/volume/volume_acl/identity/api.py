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


from cinder.db import base


class API(base.Base):
    """Interface for Identity Service."""

    def check_user_in_group(self, user_id, group_id):
        return False

    def check_user_is_admin(self, user_id, projects):
        return False

    def get_user(self, subject):
        return subject

    def get_group(self, subject):
        return subject
