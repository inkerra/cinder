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

NoPermission, Read, Write, PermissionRead, PermissionWrite, \
    ReadAndPermissionRead, WriteAndPermissionRead, FullAccess, \
    ReadAndPermissionWrite = range(9)


def aggregate(a, b):
    if a == b or a == FullAccess or b == FullAccess:
        return a
    if a == NoPermission:
        return b
    if b == NoPermission:
        return a
    p = set([a, b])
    if p == set([Read, Write]):
        return Write
    if p == set([Read, PermissionRead]):
        return ReadAndPermissionRead
    if p == set([Read, PermissionWrite]):
        return ReadAndPermissionWrite
    if p == set([Read, ReadAndPermissionRead]):
        return ReadAndPermissionRead
    if p == set([Read, WriteAndPermissionRead]):
        return WriteAndPermissionRead
    if p == set([Read, WriteAndPermissionRead]):
        return WriteAndPermissionRead
    if p == set([Write, PermissionRead]):
        return WriteAndPermissionRead
    if p == set([Write, PermissionWrite]):
        return FullAccess
    if p == set([Write, ReadAndPermissionRead]):
        return WriteAndPermissionRead
    if p == set([Write, WriteAndPermissionRead]):
        return WriteAndPermissionRead
    if p == set([PermissionRead, PermissionWrite]):
        return PermissionWrite
    if p == set([PermissionRead, ReadAndPermissionRead]):
        return ReadAndPermissionRead
    if p == set([PermissionRead, WriteAndPermissionRead]):
        return WriteAndPermissionRead
    if p == set([PermissionWrite, ReadAndPermissionRead]):
        return ReadAndPermissionWrite
    if p == set([PermissionWrite, ReadAndPermissionRead]):
        return ReadAndPermissionWrite
    if p == set([PermissionWrite, WriteAndPermissionRead]):
        return FullAccess
    if p == set([ReadAndPermissionRead, WriteAndPermissionRead]):
        return WriteAndPermissionRead
    return a
