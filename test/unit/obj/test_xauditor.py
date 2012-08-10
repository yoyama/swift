# Copyright (c) 2010-2012 OpenStack, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from test import unit
import unittest
import tempfile
import os
import time
from contextlib import contextmanager
from shutil import rmtree
from hashlib import md5
from tempfile import mkdtemp
from test.unit import FakeLogger
from swift.obj import auditor, xauditor
from swift.obj import server as object_server
from swift.obj.server import DiskFile, write_metadata, DATADIR
from swift.obj import replicator as object_replicator
from swift.obj.replicator import PICKLE_PROTOCOL, ONE_WEEK, HASH_FILE, \
    invalidate_hash
from swift.obj.xauditor import HSEXPIRE_FILE, SuffixExpireWorker, \
    ObjectXAuditor
from swift.common.utils import hash_path, mkdirs, normalize_timestamp, \
    renamer, storage_directory
from swift.common.exceptions import AuditException


class TestXAuditor(unittest.TestCase):

    def setUp(self):
        self.testdir = os.path.join(mkdtemp(), 'tmp_test_object_xauditor')
        self.devices = os.path.join(self.testdir, 'node')
        self.logger = FakeLogger()
        rmtree(self.testdir, ignore_errors=1)

        mkdirs(os.path.join(self.devices, 'sda'))
        mkdirs(os.path.join(self.devices, 'sdb'))

        self.objects_path_sda = os.path.join(self.devices,
                                             'sda', 'objects')
        self.objects_path_sdb = os.path.join(self.devices,
                                             'sdb', 'objects')
        self.objects_path_all = [self.objects_path_sda,
                                 self.objects_path_sdb]

        for path in self.objects_path_all:
            os.mkdir(path)
            for part in ['0', '1', '2', '3']:
                os.mkdir(os.path.join(path, part))

        self.part_path_sda = []
        self.part_path_sdb = []
        for part in ['0', '1', '2', '3']:
            self.part_path_sda.append(os.path.join(self.objects_path_sda,
                                                   part))
            self.part_path_sdb.append(os.path.join(self.objects_path_sdb,
                                                   part))

        self.conf = dict(
            devices=self.devices,
            mount_check='false',
            expire_age='2')

        self.disk_file = self.save_object(1024, 'sda', '0', 'a', 'c', 'o')
        self.part_path = os.path.join(self.disk_file.device_path, DATADIR, '0')
        self.suffixes = [s for s in os.listdir(self.part_path)
                         if len(s) == 3]

        self.disk_files_sdb = []
        self.disk_files_sdb.append(self.save_object(1024, 'sdb',
                                                    '0', 'a', 'c', 'o'))
        self.disk_files_sdb.append(self.save_object(1024, 'sdb',
                                                    '0', 'a', 'c', 'o2'))
        self.disk_files_sdb.append(self.save_object(1024, 'sdb',
                                                    '1', 'a', 'c', 'o'))
        self.disk_files_sdb.append(self.save_object(1024, 'sdb',
                                                    '2', 'a', 'c', 'o'))
        self.disk_files_sdb.append(self.save_object(1024, 'sdb',
                                                    '3', 'a', 'c', 'o'))

    def save_object(self, size, dev, part, account, container, obj):
        disk_file = DiskFile(self.devices, dev, part, account, container,
                             obj, self.logger)

        data = '0' * size
        etag = md5()
        with disk_file.mkstemp() as (fd, tmppath):
            os.write(fd, data)
            etag.update(data)
            etag = etag.hexdigest()
            timestamp = str(normalize_timestamp(time.time()))
            metadata = {
                'ETag': etag,
                'X-Timestamp': timestamp,
                'Content-Length': str(os.fstat(fd).st_size),
            }
            disk_file.put(fd, tmppath, metadata)
            return disk_file

    def tearDown(self):
        rmtree(os.path.dirname(self.testdir), ignore_errors=1)
        unit.xattr_data = {}

    def test_object_xaudit_get_pkl(self):
        self.seworker = xauditor.SuffixExpireWorker(self.conf)
        hashes = self.seworker.get_pkl(os.path.join(self.part_path, HASH_FILE))
        self.assertEquals(len(hashes.keys()), 0)

        object_replicator.get_hashes(self.part_path, recalculate=self.suffixes)
        hashes = self.seworker.get_pkl(os.path.join(self.part_path, HASH_FILE))
        self.assertEquals(len(hashes.keys()), 1)

    def test_object_xaudit_update_hsexpire_pkl(self):
        self.seworker = xauditor.SuffixExpireWorker(self.conf)

        '''
        No hashes.pkl and expire_hashes file.
        '''
        suffixes = self.seworker.update_hsexpire_pkl(self.part_path)
        hsexpire = self.seworker.get_pkl(os.path.join(self.part_path,
                                                      HSEXPIRE_FILE))
        self.assertEquals(len(hsexpire.keys()), 0)
        self.assertEquals(len(suffixes), 0)

        '''
        a suffix in hashes.pkl file.
        '''
        object_replicator.get_hashes(self.part_path, recalculate=self.suffixes)
        suffixes = self.seworker.update_hsexpire_pkl(self.part_path)
        hsexpire = self.seworker.get_pkl(os.path.join(self.part_path,
                                                      HSEXPIRE_FILE))
        self.assertEquals(len(hsexpire.keys()), 1)
        self.assertEquals(len(suffixes), 0)

        '''
        a suffix added. hashes.pkl and expire_hash.pkl exist.
        '''
        for i in range(0, 10):
            disk_file2 = self.save_object(1024, 'sda', '0', 'a', 'c',
                                          'obj%d' % i)
            if(self.disk_file.datadir[-3:] != disk_file2.datadir[-3:]):
                break
        object_replicator.get_hashes(self.part_path, do_listdir=True)
        suffixes = self.seworker.update_hsexpire_pkl(self.part_path)
        hsexpire = self.seworker.get_pkl(os.path.join(self.part_path,
                                                      HSEXPIRE_FILE))
        self.assertEquals(len(hsexpire.keys()), 2)
        self.assertEquals(len(suffixes), 0)

        '''
        Then remove suffix except for the added in previous test.
        '''
        for s in self.suffixes:
            rmtree(os.path.join(self.part_path, s))
        object_replicator.get_hashes(self.part_path, recalculate=self.suffixes)
        suffixes = self.seworker.update_hsexpire_pkl(self.part_path)
        hsexpire = self.seworker.get_pkl(os.path.join(self.part_path,
                                                      HSEXPIRE_FILE))
        hashes = self.seworker.get_pkl(os.path.join(self.part_path,
                                                      HASH_FILE))
        self.assertEquals(len(hsexpire.keys()), len(hashes))
        self.assertEquals(len(suffixes), 0)

        '''
        a suffix expired
        '''
        time.sleep(int(self.conf.get('expire_age')) + 1)
        suffixes = self.seworker.update_hsexpire_pkl(self.part_path)
        hsexpire = self.seworker.get_pkl(os.path.join(self.part_path,
                                                      HSEXPIRE_FILE))
        self.assertEquals(len(hsexpire.keys()), 1)
        self.assertEquals(len(suffixes), 1)

    def test_object_xaudit_check_partition(self):
        self.seworker = xauditor.SuffixExpireWorker(self.conf)

        '''
        Empty parition
        '''
        self.seworker.check_partition(self.part_path)

        '''
        No exist partition dir
        '''
        self.seworker.check_partition("%s_noexist" % self.part_path)

    def test_object_xaudit_check_all_partitions(self):
        self.seworker = xauditor.SuffixExpireWorker(self.conf)

        for pp in self.part_path_sdb:
            object_replicator.get_hashes(pp, do_listdir=True)

        self.seworker.check_all_partitions(self.objects_path_sdb)
        for pp in self.part_path_sdb:
            hf = os.path.join(pp, HASH_FILE)
            hsef = os.path.join(pp, HSEXPIRE_FILE)
            self.assertEqual(os.path.isfile(hf), True)
            self.assertEqual(os.path.isfile(hsef), True)

    def test_run_onece(self):
        class SuffixExpireWorkerMock(object):
            datadir = None

            def mock_check_all_devices(self, datadir):
                self.datadir = datadir

        @contextmanager
        def _mock_suffix_expire_worker(mock):
            original = SuffixExpireWorker.check_all_devices
            SuffixExpireWorker.check_all_devices = mock.mock_check_all_devices
            yield
            SuffixExpireWorker.check_all_devices = original

        my_mock = SuffixExpireWorkerMock()
        my_xauditor = ObjectXAuditor(dict(devices=self.devices,
                                          mount_check='false'))
        self.assertEquals(my_mock.datadir, None)
        with _mock_suffix_expire_worker(my_mock):
            my_xauditor.run_once()
            self.assertEquals(my_mock.datadir, object_server.DATADIR)

    def test_run_forever(self):

        class StopForever(Exception):
            pass

        class ObjectXAuditorMock(object):
            check_args = ()
            check_kwargs = {}

            def mock_run_once(self, *args, **kwargs):
                self.check_args = args
                self.check_kwargs = kwargs

            def mock_sleep(self):
                raise StopForever('stop')

        my_xauditor = xauditor.ObjectXAuditor(dict(devices=self.devices,
                                                   mount_check='false'))
        mocker = ObjectXAuditorMock()
        my_xauditor.run_once = mocker.mock_run_once
        my_xauditor._sleep = mocker.mock_sleep
        try:
            self.assertRaises(StopForever, my_xauditor.run_forever)
            self.assertEquals(mocker.check_args, ())
            self.assertEquals(mocker.check_kwargs['mode'], 'forever')
        finally:
            pass

if __name__ == '__main__':
    unittest.main()
