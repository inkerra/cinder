# Copyright 2013 Canonical Ltd.
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

"""Ceph Backup Service Implementation.

This driver supports backing up volumes of any type to a Ceph backend store. It
is also capable of detecting whether the volume to be backed up is a Ceph RBD
volume and if so, attempts to perform incremental/differential backups.

Support is also included for the following in the case of source volume being a
Ceph RBD volume:

    * backing up within the same Ceph pool (not recommended)
    * backing up between different Ceph pools
    * backing up between different Ceph clusters

At the time of writing, differential backup support in Ceph/librbd was quite
new so this driver accounts for this by first attempting differential backup
and falling back to full backup/copy if the former fails.

If incremental backups are used, multiple backups of the same volume are stored
as snapshots so that minimal space is consumed in the backup store and
restoring the volume takes a far reduced amount of time compared to a full
copy.

Note that Cinder supports restoring to a new volume or the original volume the
backup was taken from. For the latter case, a full copy is enforced since this
was deemed the safest action to take. It is therefore recommended to always
restore to a new volume (default).
"""

import eventlet
import os
import re
import time

from cinder.backup.driver import BackupDriver
from cinder import exception
from cinder.openstack.common import log as logging
from cinder import units
from cinder import utils
import cinder.volume.drivers as drivers
from oslo.config import cfg

try:
    import rados
    import rbd
except ImportError:
    rados = None
    rbd = None

LOG = logging.getLogger(__name__)

service_opts = [
    cfg.StrOpt('backup_ceph_conf', default='/etc/ceph/ceph.conf',
               help='Ceph config file to use.'),
    cfg.StrOpt('backup_ceph_user', default='cinder',
               help='the Ceph user to connect with'),
    cfg.IntOpt('backup_ceph_chunk_size', default=(units.MiB * 128),
               help='the chunk size in bytes that a backup will be broken '
                    'into before transfer to backup store'),
    cfg.StrOpt('backup_ceph_pool', default='backups',
               help='the Ceph pool to backup to'),
    cfg.IntOpt('backup_ceph_stripe_unit', default=0,
               help='RBD stripe unit to use when creating a backup image'),
    cfg.IntOpt('backup_ceph_stripe_count', default=0,
               help='RBD stripe count to use when creating a backup image')
]

CONF = cfg.CONF
CONF.register_opts(service_opts)


class CephBackupDriver(BackupDriver):
    """Backup up Cinder volumes to Ceph Object Store.

    This class enables backing up Cinder volumes to a Ceph object store.
    Backups may be stored in their own pool or even cluster. Store location is
    defined by the Ceph conf file and Service config options supplied.

    If the source volume is itself an RBD volume, the backup will be performed
    using incremental differential backups which *should* give a performance
    gain.
    """

    def __init__(self, context, db_driver=None, execute=None):
        super(CephBackupDriver, self).__init__(db_driver)
        self.rbd = rbd
        self.rados = rados
        self.context = context
        self.chunk_size = CONF.backup_ceph_chunk_size
        self._execute = execute or utils.execute

        if self._supports_stripingv2:
            self.rbd_stripe_unit = CONF.backup_ceph_stripe_unit
            self.rbd_stripe_count = CONF.backup_ceph_stripe_count
        else:
            LOG.info(_("rbd striping not supported - ignoring configuration "
                       "settings for rbd striping"))
            self.rbd_stripe_count = 0
            self.rbd_stripe_unit = 0

        self._ceph_backup_user = self._utf8(CONF.backup_ceph_user)
        self._ceph_backup_pool = self._utf8(CONF.backup_ceph_pool)
        self._ceph_backup_conf = self._utf8(CONF.backup_ceph_conf)

    @staticmethod
    def _utf8(s):
        """Ensure string s is utf8 (i.e. not unicode)."""
        if isinstance(s, str):
            return s

        return s.encode('utf8')

    def _validate_string_args(self, *args):
        """Ensure all args are non-None and non-empty."""
        return all(args)

    def _ceph_args(self, user, conf=None, pool=None):
        """Create default ceph args for executing rbd commands.

        If no --conf is provided, rbd will look in the default locations e.g.
        /etc/ceph/ceph.conf
        """

        # Make sure user arg is valid since rbd command may not fail if
        # invalid/no user provided, resulting in unexpected behaviour.
        if not self._validate_string_args(user):
            raise exception.BackupInvalidCephArgs(_("invalid user '%s'") %
                                                  (user))

        args = ['--id', user]
        if conf:
            args += ['--conf', conf]
        if pool:
            args += '--pool', pool

        return args

    @property
    def _supports_layering(self):
        """Determine if copy-on-write is supported by our version of librbd."""
        return hasattr(self.rbd, 'RBD_FEATURE_LAYERING')

    @property
    def _supports_stripingv2(self):
        """Determine if striping is supported by our version of librbd."""
        return hasattr(self.rbd, 'RBD_FEATURE_STRIPINGV2')

    def _get_rbd_support(self):
        """Determine RBD features supported by our version of librbd."""
        old_format = True
        features = 0
        if self._supports_layering:
            old_format = False
            features |= self.rbd.RBD_FEATURE_LAYERING
        if self._supports_stripingv2:
            old_format = False
            features |= self.rbd.RBD_FEATURE_STRIPINGV2

        return (old_format, features)

    def _connect_to_rados(self, pool=None):
        """Establish connection to the backup Ceph cluster."""
        client = self.rados.Rados(rados_id=self._ceph_backup_user,
                                  conffile=self._ceph_backup_conf)
        try:
            client.connect()
            pool_to_open = self._utf8(pool or self._ceph_backup_pool)
            ioctx = client.open_ioctx(pool_to_open)
            return client, ioctx
        except self.rados.Error:
            # shutdown cannot raise an exception
            client.shutdown()
            raise

    def _disconnect_from_rados(self, client, ioctx):
        """Terminate connection with the backup Ceph cluster."""
        # closing an ioctx cannot raise an exception
        ioctx.close()
        client.shutdown()

    def _get_backup_base_name(self, volume_id, backup_id=None,
                              diff_format=False):
        """Return name of base image used for backup.

        Incremental backups use a new base name so we support old and new style
        format.
        """
        # Ensure no unicode
        if diff_format:
            return self._utf8("volume-%s.backup.base" % (volume_id))
        else:
            if backup_id is None:
                msg = _("backup_id required")
                raise exception.InvalidParameterValue(msg)
            return self._utf8("volume-%s.backup.%s" % (volume_id, backup_id))

    def _transfer_data(self, src, src_name, dest, dest_name, length):
        """Transfer data between files (Python IO objects)."""
        LOG.debug(_("transferring data between '%(src)s' and '%(dest)s'") %
                  {'src': src_name, 'dest': dest_name})

        chunks = int(length / self.chunk_size)
        LOG.debug(_("%(chunks)s chunks of %(bytes)s bytes to be transferred") %
                  {'chunks': chunks, 'bytes': self.chunk_size})

        for chunk in xrange(0, chunks):
            before = time.time()
            data = src.read(self.chunk_size)
            dest.write(data)
            dest.flush()
            delta = (time.time() - before)
            rate = (self.chunk_size / delta) / 1024
            LOG.debug((_("transferred chunk %(chunk)s of %(chunks)s "
                         "(%(rate)dK/s)") %
                       {'chunk': chunk, 'chunks': chunks,
                        'rate': rate}))

            # yield to any other pending backups
            eventlet.sleep(0)

        rem = int(length % self.chunk_size)
        if rem:
            LOG.debug(_("transferring remaining %s bytes") % (rem))
            data = src.read(rem)
            dest.write(data)
            dest.flush()
            # yield to any other pending backups
            eventlet.sleep(0)

    def _create_base_image(self, name, size, rados_client):
        """Create a base backup image.

        This will be the base image used for storing differential exports.
        """
        LOG.debug(_("creating base image '%s'") % (name))
        old_format, features = self._get_rbd_support()
        self.rbd.RBD().create(ioctx=rados_client.ioctx,
                              name=name,
                              size=size,
                              old_format=old_format,
                              features=features,
                              stripe_unit=self.rbd_stripe_unit,
                              stripe_count=self.rbd_stripe_count)

    def _delete_backup_snapshots(self, rados_client, base_name, backup_id):
        """Delete any snapshots associated with this backup.

        A backup should have at most *one* associated snapshot.

        This is required before attempting to delete the base image. The
        snapshots on the original volume can be left as they will be purged
        when the volume is deleted.
        """
        backup_snaps = None
        base_rbd = self.rbd.Image(rados_client.ioctx, base_name)
        try:
            snap_name = self._get_backup_snap_name(base_rbd, base_name,
                                                   backup_id)
            if snap_name:
                LOG.debug(_("deleting backup snapshot='%s'") % (snap_name))
                base_rbd.remove_snap(snap_name)
            else:
                LOG.debug(_("no backup snapshot to delete"))

            # Now check whether any snapshots remain on the base image
            backup_snaps = self.get_backup_snaps(base_rbd)
        finally:
            base_rbd.close()

        if backup_snaps:
            return len(backup_snaps)
        else:
            return 0

    def _try_delete_base_image(self, backup_id, volume_id, base_name=None):
        """Try to delete backup RBD image.

        If the rbd image is a base image for incremental backups, it may have
        snapshots. Delete the snapshot associated with backup_id and if the
        image has no more snapshots, delete it. Otherwise return.

        If no base name is provided try normal (full) format then diff format
        image name.

        If a base name is provided but does not exist, ImageNotFound will be
        raised.

        If the image is busy, a number of retries will be performed if
        ImageBusy is received, after which the exception will be propagated to
        the caller.
        """
        retries = 3
        delay = 5
        try_diff_format = False

        if base_name is None:
            try_diff_format = True

            base_name = self._get_backup_base_name(volume_id, backup_id)
            LOG.debug(_("trying diff format name format basename='%s'") %
                      (base_name))

        with drivers.rbd.RADOSClient(self) as client:
            rbd_exists, base_name = \
                self._rbd_image_exists(base_name, volume_id, client,
                                       try_diff_format=try_diff_format)
            if not rbd_exists:
                raise self.rbd.ImageNotFound(_("image %s not found") %
                                             (base_name))

            while retries >= 0:
                # First delete associated snapshot (if exists)
                rem = self._delete_backup_snapshots(client, base_name,
                                                    backup_id)
                if rem:
                    msg = (_("base image still has %s snapshots so not "
                             "deleting base image") % (rem))
                    LOG.info(msg)
                    return

                LOG.info(_("deleting base image='%s'") % (base_name))
                # Delete base if no more snapshots
                try:
                    self.rbd.RBD().remove(client.ioctx, base_name)
                except self.rbd.ImageBusy as exc:
                    # Allow a retry if the image is busy
                    if retries > 0:
                        LOG.info((_("image busy, retrying %(retries)s "
                                    "more time(s) in %(delay)ss") %
                                  {'retries': retries, 'delay': delay}))
                        eventlet.sleep(delay)
                    else:
                        LOG.error(_("max retries reached - raising error"))
                        raise exc
                else:
                    LOG.debug(_("base backup image='%s' deleted)") %
                              (base_name))
                    retries = 0
                finally:
                    retries -= 1

    def _rbd_diff_transfer(self, src_name, src_pool, dest_name, dest_pool,
                           src_user, src_conf, dest_user, dest_conf,
                           src_snap=None, from_snap=None):
        """Backup only extents changed between two points.

        If no snapshot is provided, the diff extents will be all those changed
        since the rbd volume/base was created, otherwise it will be those
        changed since the snapshot was created.
        """
        LOG.debug(_("performing differential transfer from '%(src)s' to "
                    "'%(dest)s'") %
                  {'src': src_name, 'dest': dest_name})

        # NOTE(dosaboy): Need to be tolerant of clusters/clients that do
        # not support these operations since at the time of writing they
        # were very new.

        src_ceph_args = self._ceph_args(src_user, src_conf, pool=src_pool)
        dest_ceph_args = self._ceph_args(dest_user, dest_conf, pool=dest_pool)

        try:
            cmd = ['rbd', 'export-diff'] + src_ceph_args
            if from_snap is not None:
                cmd += ['--from-snap', from_snap]
            if src_snap:
                path = self._utf8("%s/%s@%s" % (src_pool, src_name, src_snap))
            else:
                path = self._utf8("%s/%s" % (src_pool, src_name))
            cmd += [path, '-']
            out, err = self._execute(*cmd)
        except (exception.ProcessExecutionError, exception.Error) as exc:
            LOG.info(_("rbd export-diff failed - %s") % (str(exc)))
            raise exception.BackupRBDOperationFailed("rbd export-diff failed")

        try:
            cmd = ['rbd', 'import-diff'] + dest_ceph_args
            cmd += ['-', self._utf8("%s/%s" % (dest_pool, dest_name))]
            out, err = self._execute(*cmd, process_input=out)
        except (exception.ProcessExecutionError, exception.Error) as exc:
            LOG.info(_("rbd import-diff failed - %s") % (str(exc)))
            raise exception.BackupRBDOperationFailed("rbd import-diff failed")

    def _rbd_image_exists(self, name, volume_id, client,
                          try_diff_format=False):
        """Return tuple (exists, name)."""
        rbds = self.rbd.RBD().list(client.ioctx)
        if name not in rbds:
            msg = _("image '%s' not found - trying diff format name") % (name)
            LOG.debug(msg)
            if try_diff_format:
                name = self._get_backup_base_name(volume_id, diff_format=True)
                if name not in rbds:
                    msg = _("diff format image '%s' not found") % (name)
                    LOG.debug(msg)
                    return False, name
            else:
                return False, name

        return True, name

    def _snap_exists(self, base_name, snap_name, client):
        """Return True if snapshot exists in base image."""
        base_rbd = self.rbd.Image(client.ioctx, base_name)
        try:
            snaps = base_rbd.list_snaps()
        finally:
            base_rbd.close()

        if snaps is None:
            return False

        for snap in snaps:
            if snap['name'] == snap_name:
                return True

        return False

    def _backup_rbd(self, backup_id, volume_id, volume_file, volume_name,
                    length):
        """Create a incremental backup from an RBD image."""
        rbd_user = volume_file.rbd_user
        rbd_pool = volume_file.rbd_pool
        rbd_conf = volume_file.rbd_conf
        source_rbd_image = volume_file.rbd_image

        # Identify our --from-snap point (if one exists)
        from_snap = self._get_most_recent_snap(source_rbd_image)
        LOG.debug(_("using --from-snap '%s'") % from_snap)

        backup_name = self._get_backup_base_name(volume_id, diff_format=True)
        image_created = False
        force_full_backup = False
        with drivers.rbd.RADOSClient(self, self._ceph_backup_pool) as client:
            # If from_snap does not exist in the destination, this implies a
            # previous backup has failed. In this case we will force a full
            # backup.
            #
            # TODO(dosaboy): find a way to repair the broken backup
            #
            if backup_name not in self.rbd.RBD().list(ioctx=client.ioctx):
                # If a from_snap is defined then we cannot proceed (see above)
                if from_snap is not None:
                    force_full_backup = True

                # Create new base image
                self._create_base_image(backup_name, length, client)
                image_created = True
            else:
                # If a from_snap is defined but does not exist in the back base
                # then we cannot proceed (see above)
                if not self._snap_exists(backup_name, from_snap, client):
                    force_full_backup = True

        if force_full_backup:
            errmsg = (_("snap='%(snap)s' does not exist in base "
                        "image='%(base)s' - aborting incremental backup") %
                      {'snap': from_snap, 'base': backup_name})
            LOG.info(errmsg)
            # Raise this exception so that caller can try another
            # approach
            raise exception.BackupRBDOperationFailed(errmsg)

        # Snapshot source volume so that we have a new point-in-time
        new_snap = self._get_new_snap_name(backup_id)
        LOG.debug(_("creating backup snapshot='%s'") % (new_snap))
        source_rbd_image.create_snap(new_snap)

        # Attempt differential backup. If this fails, perhaps because librbd
        # or Ceph cluster version does not support it, do a full backup
        # instead.
        #
        # TODO(dosaboy): find a way to determine if the operation is supported
        #                rather than brute force approach.
        try:
            before = time.time()
            self._rbd_diff_transfer(volume_name, rbd_pool, backup_name,
                                    self._ceph_backup_pool,
                                    src_user=rbd_user,
                                    src_conf=rbd_conf,
                                    dest_user=self._ceph_backup_user,
                                    dest_conf=self._ceph_backup_conf,
                                    src_snap=new_snap,
                                    from_snap=from_snap)

            LOG.debug(_("differential backup transfer completed in %.4fs") %
                      (time.time() - before))

            # We don't need the previous snapshot (if there was one) anymore so
            # delete it.
            if from_snap:
                source_rbd_image.remove_snap(from_snap)

        except exception.BackupRBDOperationFailed:
            LOG.debug(_("differential backup transfer failed"))

            # Clean up if image was created as part of this operation
            if image_created:
                self._try_delete_base_image(backup_id, volume_id,
                                            base_name=backup_name)

            # Delete snapshot
            LOG.debug(_("deleting backup snapshot='%s'") % (new_snap))
            source_rbd_image.remove_snap(new_snap)

            # Re-raise the exception so that caller can try another approach
            raise

    def _file_is_rbd(self, volume_file):
        """Returns True if the volume_file is actually an RBD image."""
        return hasattr(volume_file, 'rbd_image')

    def _full_backup(self, backup_id, volume_id, src_volume, src_name, length):
        """Perform a full backup of src volume.

        First creates a base backup image in our backup location then performs
        an chunked copy of all data from source volume to a new backup rbd
        image.
        """
        backup_name = self._get_backup_base_name(volume_id, backup_id)

        with drivers.rbd.RADOSClient(self, self._ceph_backup_pool) as client:
            # First create base backup image
            old_format, features = self._get_rbd_support()
            LOG.debug(_("creating base image='%s'") % (backup_name))
            self.rbd.RBD().create(ioctx=client.ioctx,
                                  name=backup_name,
                                  size=length,
                                  old_format=old_format,
                                  features=features,
                                  stripe_unit=self.rbd_stripe_unit,
                                  stripe_count=self.rbd_stripe_count)

            LOG.debug(_("copying data"))
            dest_rbd = self.rbd.Image(client.ioctx, backup_name)
            try:
                rbd_meta = drivers.rbd.RBDImageMetadata(dest_rbd,
                                                        self._ceph_backup_pool,
                                                        self._ceph_backup_user,
                                                        self._ceph_backup_conf)
                rbd_fd = drivers.rbd.RBDImageIOWrapper(rbd_meta)
                self._transfer_data(src_volume, src_name, rbd_fd, backup_name,
                                    length)
            finally:
                dest_rbd.close()

    @staticmethod
    def backup_snapshot_name_pattern():
        """Returns the pattern used to match backup snapshots.

        It is essential that snapshots created for purposes other than backups
        do not have this name format.
        """
        return r"^backup\.([a-z0-9\-]+?)\.snap\.(.+)$"

    @classmethod
    def get_backup_snaps(cls, rbd_image, sort=False):
        """Get all backup snapshots for the given rbd image.

        NOTE: this call is made public since these snapshots must be deleted
              before the base volume can be deleted.
        """
        snaps = rbd_image.list_snaps()

        backup_snaps = []
        for snap in snaps:
            search_key = cls.backup_snapshot_name_pattern()
            result = re.search(search_key, snap['name'])
            if result:
                backup_snaps.append({'name': result.group(0),
                                     'backup_id': result.group(1),
                                     'timestamp': result.group(2)})

        if sort:
            # Sort into ascending order of timestamp
            backup_snaps.sort(key=lambda x: x['timestamp'], reverse=True)

        return backup_snaps

    def _get_new_snap_name(self, backup_id):
        return self._utf8("backup.%s.snap.%s" % (backup_id, time.time()))

    def _get_backup_snap_name(self, rbd_image, name, backup_id):
        """Return the name of the snapshot associated with backup_id.

        The rbd image provided must be the base image used for an incremental
        backup.

        A back is only allowed to have one associated snapshot. If more than
        one is found, exception.BackupOperationError is raised.
        """
        snaps = self.get_backup_snaps(rbd_image)

        LOG.debug(_("looking for snapshot of backup base '%s'") % (name))

        if not snaps:
            LOG.debug(_("backup base '%s' has no snapshots") % (name))
            return None

        snaps = [snap['name'] for snap in snaps
                 if snap['backup_id'] == backup_id]

        if not snaps:
            LOG.debug(_("backup '%s' has no snapshot") % (backup_id))
            return None

        if len(snaps) > 1:
            msg = (_("backup should only have one snapshot but instead has %s")
                   % (len(snaps)))
            LOG.error(msg)
            raise exception.BackupOperationError(msg)

        LOG.debug(_("found snapshot '%s'") % (snaps[0]))
        return snaps[0]

    def _get_most_recent_snap(self, rbd_image):
        """Get the most recent backup snapshot of the provided image.

        Returns name of most recent backup snapshot or None if there are no
        backup snapshot.
        """
        backup_snaps = self.get_backup_snaps(rbd_image, sort=True)
        if not backup_snaps:
            return None

        return backup_snaps[0]['name']

    def _get_volume_size_gb(self, volume):
        """Return the size in gigabytes of the given volume.

        Raises exception.InvalidParameterValue if voluem size is 0.
        """
        if int(volume['size']) == 0:
            raise exception.InvalidParameterValue("need non-zero volume size")

        return int(volume['size']) * units.GiB

    def backup(self, backup, volume_file):
        """Backup the given volume to Ceph object store.

        If the source volume is an RBD we will attempt to do an
        incremental/differential backup, otherwise a full copy is performed.
        If this fails we will attempt to fall back to full copy.
        """
        backup_id = backup['id']
        volume = self.db.volume_get(self.context, backup['volume_id'])
        volume_id = volume['id']
        volume_name = volume['name']

        LOG.debug(_("Starting backup of volume='%s'") % volume_name)

        # Ensure we are at the beginning of the volume
        volume_file.seek(0)
        length = self._get_volume_size_gb(volume)

        do_full_backup = False
        if self._file_is_rbd(volume_file):
            # If volume an RBD, attempt incremental backup.
            try:
                self._backup_rbd(backup_id, volume_id, volume_file,
                                 volume_name, length)
            except exception.BackupRBDOperationFailed:
                LOG.debug(_("forcing full backup"))
                do_full_backup = True
        else:
            do_full_backup = True

        if do_full_backup:
            self._full_backup(backup_id, volume_id, volume_file,
                              volume_name, length)

        self.db.backup_update(self.context, backup_id,
                              {'container': self._ceph_backup_pool})

        LOG.debug(_("backup '%s' finished.") % (backup_id))

    def _full_restore(self, backup_id, volume_id, dest_file, dest_name,
                      length, src_snap=None):
        """Restore the given volume file from backup RBD.

        This will result in all extents being copied from source to destination
        """
        with drivers.rbd.RADOSClient(self, self._ceph_backup_pool) as client:

            if src_snap:
                # If a source snapshot is provided we assume the base is diff
                # format.
                backup_name = self._get_backup_base_name(volume_id,
                                                         diff_format=True)
            else:
                backup_name = self._get_backup_base_name(volume_id, backup_id)

            # Retrieve backup volume
            src_rbd = self.rbd.Image(client.ioctx, backup_name,
                                     snapshot=src_snap)
            try:
                rbd_meta = drivers.rbd.RBDImageMetadata(src_rbd,
                                                        self._ceph_backup_pool,
                                                        self._ceph_backup_user,
                                                        self._ceph_backup_conf)
                rbd_fd = drivers.rbd.RBDImageIOWrapper(rbd_meta)
                self._transfer_data(rbd_fd, backup_name, dest_file, dest_name,
                                    length)
            finally:
                src_rbd.close()

    def _restore_rbd(self, base_name, volume_file, volume_name, restore_point):
        """Restore RBD volume from RBD image."""
        rbd_user = volume_file.rbd_user
        rbd_pool = volume_file.rbd_pool
        rbd_conf = volume_file.rbd_conf

        LOG.debug(_("trying incremental restore from base='%(base)s' "
                    "snap='%(snap)s'") %
                  {'base': base_name, 'snap': restore_point})
        before = time.time()
        try:
            self._rbd_diff_transfer(base_name, self._ceph_backup_pool,
                                    volume_name, rbd_pool,
                                    src_user=self._ceph_backup_user,
                                    src_conf=self._ceph_backup_conf,
                                    dest_user=rbd_user, dest_conf=rbd_conf,
                                    src_snap=restore_point)
        except exception.BackupRBDOperationFailed:
            LOG.exception(_("differential restore failed, trying full "
                            "restore"))
            raise

        LOG.debug(_("restore transfer completed in %.4fs") %
                  (time.time() - before))

    def _num_backup_snaps(self, backup_base_name):
        """Return the number of snapshots that exist on the base image."""
        with drivers.rbd.RADOSClient(self, self._ceph_backup_pool) as client:
            base_rbd = self.rbd.Image(client.ioctx, backup_base_name)
            try:
                snaps = self.get_backup_snaps(base_rbd)
            finally:
                base_rbd.close()

        if snaps:
            return len(snaps)
        else:
            return 0

    def _get_restore_point(self, base_name, backup_id):
        """Get restore point snapshot name for incremental backup.

        If the backup was not incremental None is returned.
        """
        with drivers.rbd.RADOSClient(self, self._ceph_backup_pool) as client:
            base_rbd = self.rbd.Image(client.ioctx, base_name)
            try:
                restore_point = self._get_backup_snap_name(base_rbd, base_name,
                                                           backup_id)
            finally:
                base_rbd.close()

        return restore_point

    def _rbd_has_extents(self, rbd_volume):
        """Check whether the given rbd volume has extents.

        Return True if has extents, otherwise False.
        """
        extents = []

        def iter_cb(offset, length, exists):
            if exists:
                extents.append(length)

        rbd_volume.diff_iterate(0, rbd_volume.size(), None, iter_cb)

        if extents:
            LOG.debug("rbd has %s extents" % (sum(extents)))
            return True

        return False

    def _diff_restore_allowed(self, base_name, backup, volume, volume_file,
                              rados_client):
        """Determine whether a differential restore is possible/allowed.

        In order for a differential restore to be performed we need:
            * destination volume must be RBD
            * destination volume must have zero extents
            * backup base image must exist
            * backup must have a restore point

        Returns True if differential restore is allowed, False otherwise.
        """
        not_allowed = (False, None)

        # If the volume we are restoring to is the volume the backup was made
        # from, force a full restore since a diff will not work in this case.
        if volume['id'] == backup['volume_id']:
            LOG.debug("dest volume is original volume - forcing full copy")
            return not_allowed

        if self._file_is_rbd(volume_file):
            rbd_exists, base_name = self._rbd_image_exists(base_name,
                                                           backup['volume_id'],
                                                           rados_client)

            if not rbd_exists:
                return not_allowed

            # Get the restore point. If no restore point is found, we assume
            # that the backup was not performed using diff/incremental methods
            # so we enforce full copy.
            restore_point = self._get_restore_point(base_name, backup['id'])
            if restore_point:
                # If the destination volume has extents we cannot allow a diff
                # restore.
                if self._rbd_has_extents(volume_file.rbd_image):
                    # We return the restore point so that a full copy is done
                    # from snapshot.
                    LOG.debug("destination has extents - forcing full copy")
                    return False, restore_point

                return True, restore_point
            else:
                LOG.info(_("no restore point found for backup='%s', forcing "
                           "full copy") % (backup['id']))

        return not_allowed

    def _try_restore(self, backup, volume, volume_file):
        """Attempt to restore volume from backup."""
        volume_name = volume['name']
        backup_id = backup['id']
        backup_volume_id = backup['volume_id']
        length = int(volume['size']) * units.GiB

        base_name = self._get_backup_base_name(backup['volume_id'],
                                               diff_format=True)

        with drivers.rbd.RADOSClient(self, self._ceph_backup_pool) as client:
            diff_restore, restore_point = \
                self._diff_restore_allowed(base_name, backup, volume,
                                           volume_file, client)

        if diff_restore:
            try:
                do_full_restore = False
                self._restore_rbd(base_name, volume_file, volume_name,
                                  restore_point)
            except exception.BackupRBDOperationFailed:
                LOG.debug(_("forcing full restore"))
                do_full_restore = True
        else:
            do_full_restore = True

        if do_full_restore:
            # Otherwise full copy
            self._full_restore(backup_id, backup_volume_id, volume_file,
                               volume_name, length, src_snap=restore_point)

    def restore(self, backup, volume_id, volume_file):
        """Restore the given volume backup from Ceph object store."""
        target_volume = self.db.volume_get(self.context, volume_id)
        LOG.debug(_('starting restore from Ceph backup=%(src)s to '
                    'volume=%(dest)s') %
                  {'src': backup['id'], 'dest': target_volume['name']})

        # Ensure we are at the beginning of the volume
        volume_file.seek(0)

        try:
            self._try_restore(backup, target_volume, volume_file)

            # Be tolerant to IO implementations that do not support fileno()
            try:
                fileno = volume_file.fileno()
            except IOError:
                LOG.info(_("volume_file does not support fileno() so skipping "
                           "fsync()"))
            else:
                os.fsync(fileno)

            LOG.debug(_('restore finished.'))
        except exception.BackupOperationError as e:
            LOG.error(_('restore finished with error - %s') % (e))
            raise

    def delete(self, backup):
        """Delete the given backup from Ceph object store."""
        backup_id = backup['id']
        LOG.debug(_('delete started for backup=%s') % backup['id'])

        try:
            self._try_delete_base_image(backup['id'], backup['volume_id'])
        except self.rbd.ImageNotFound:
            msg = _("rbd image not found but continuing anyway so "
                    "that db entry can be removed")
            LOG.warning(msg)
            LOG.info(_("delete '%s' finished with warning") % (backup_id))

        LOG.debug(_("delete '%s' finished") % (backup_id))


def get_backup_driver(context):
    return CephBackupDriver(context)
