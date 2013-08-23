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
    if {a, b} == {Read, Write}:
        return Write
    if {a, b} == {Read, PermissionRead}:
        return ReadAndPermissionRead
    if {a, b} == {Read, PermissionWrite}:
        return ReadAndPermissionWrite
    if {a, b} == {Read, ReadAndPermissionRead}:
        return ReadAndPermissionRead
    if {a, b} == {Read, WriteAndPermissionRead}:
        return WriteAndPermissionRead
    if {a, b} == {Read, WriteAndPermissionRead}:
        return WriteAndPermissionRead
    if {a, b} == {Write, PermissionRead}:
        return WriteAndPermissionRead
    if {a, b} == {Write, PermissionWrite}:
        return FullAccess
    if {a, b} == {Write, ReadAndPermissionRead}:
        return WriteAndPermissionRead
    if {a, b} == {Write, WriteAndPermissionRead}:
        return WriteAndPermissionRead
    if {a, b} == {PermissionRead, PermissionWrite}:
        return PermissionWrite
    if {a, b} == {PermissionRead, ReadAndPermissionRead}:
        return ReadAndPermissionRead
    if {a, b} == {PermissionRead, WriteAndPermissionRead}:
        return WriteAndPermissionRead
    if {a, b} == {PermissionWrite, ReadAndPermissionRead}:
        return ReadAndPermissionWrite
    if {a, b} == {PermissionWrite, ReadAndPermissionRead}:
        return ReadAndPermissionWrite
    if {a, b} == {PermissionWrite, WriteAndPermissionRead}:
        return FullAccess
    if {a, b} == {ReadAndPermissionRead, WriteAndPermissionRead}:
        return WriteAndPermissionRead
    return a
