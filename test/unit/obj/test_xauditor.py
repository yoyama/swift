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
import cPickle as pickle
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

        self.device_list = ['sda', 'sdb']
        self.objects_path_all = {}
        self.part_path_all = {}
        for dl in self.device_list:
            mkdirs(os.path.join(self.devices, dl))
            objects_path = os.path.join(self.devices, dl, 'objects')
            mkdirs(objects_path)
            self.objects_path_all[dl] = objects_path
            self.part_path_all[dl] = []
            for part in range(0, 20):
                part_path = os.path.join(objects_path, '%s' % part)
                os.mkdir(part_path)
                self.part_path_all[dl].append(part_path)

        self.conf = dict(
            devices=self.devices,
            mount_check='false',
            expire_age='2')

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
        device = self.device_list[0]
        part_path = self.part_path_all[device][0]
        disk_file = self.save_object(100, device, part_path, 'a', 'c', 'o')
        suffixes = [s for s in os.listdir(part_path) if len(s) == 3]

        seworker = xauditor.SuffixExpireWorker(self.conf)
        hashes = seworker.get_pkl(os.path.join(part_path, HASH_FILE))
        self.assertEquals(len(hashes.keys()), 0)

        object_replicator.get_hashes(part_path, recalculate=suffixes)
        hashes = seworker.get_pkl(os.path.join(part_path, HASH_FILE))

        self.assertEquals(len(hashes.keys()), 1)

    def test_object_xaudit_get_pkl_2(self):
        def mock_pickle_load(path):
            raise Exception("mock_pickle_load")

        @contextmanager
        def _dummy_load(mock):
            original = pickle.load
            pickle.load = mock
            yield
            pickle.load = original

        device = self.device_list[0]
        part_path = self.part_path_all[device][0]
        disk_file = self.save_object(100, device, part_path, 'a', 'c', 'o')
        object_replicator.get_hashes(part_path, do_listdir=True)

        seworker = xauditor.SuffixExpireWorker(self.conf)
        with _dummy_load(mock_pickle_load):
            hashes = seworker.get_pkl(os.path.join(part_path, HASH_FILE))

    def test_object_xaudit_update_hsexpire_pkl(self):
        device = self.device_list[0]
        part_path = self.part_path_all[device][0]
        disk_file = self.save_object(100, device, part_path, 'a', 'c', 'o')
        suffixes = [s for s in os.listdir(part_path) if len(s) == 3]

        seworker = xauditor.SuffixExpireWorker(self.conf)

        '''
        No hashes.pkl and expire_hashes file.
        '''
        expired_suffixes = seworker.update_hsexpire_pkl(part_path)
        hsexpire = seworker.get_pkl(os.path.join(part_path,
                                                 HSEXPIRE_FILE))
        self.assertEquals(len(hsexpire.keys()), 0)

        '''
        a suffix in hashes.pkl file.
        '''
        object_replicator.get_hashes(part_path, recalculate=suffixes)
        expired_suffixes = seworker.update_hsexpire_pkl(part_path)
        hsexpire = seworker.get_pkl(os.path.join(part_path,
                                                 HSEXPIRE_FILE))
        self.assertEquals(len(hsexpire.keys()), 1)

        '''
        a suffix added. hashes.pkl and expire_hash.pkl exist.
        '''
        for i in range(0, 100):
            disk_file2 = self.save_object(1024, device, '0', 'a', 'c',
                                          'obj%d' % i)
            if(disk_file.datadir[-3:] != disk_file2.datadir[-3:]):
                break
        object_replicator.get_hashes(part_path, do_listdir=True)
        expired_suffixes = seworker.update_hsexpire_pkl(part_path)
        hsexpire = seworker.get_pkl(os.path.join(part_path,
                                                 HSEXPIRE_FILE))
        self.assertEquals(len(hsexpire.keys()), 2)

        '''
        Then remove suffix except for the added in previous test.
        '''
        for s in suffixes:
            rmtree(os.path.join(part_path, s))
        object_replicator.get_hashes(part_path, do_listdir=True)
        expired_suffixes = seworker.update_hsexpire_pkl(part_path)
        hsexpire = seworker.get_pkl(os.path.join(part_path,
                                                 HSEXPIRE_FILE))
        hashes = seworker.get_pkl(os.path.join(part_path, HASH_FILE))
        self.assertEquals(len(hsexpire.keys()), len(hashes))

        '''
        a suffix expired
        '''
        time.sleep(int(self.conf.get('expire_age')) + 1)
        expired_suffixes = seworker.update_hsexpire_pkl(part_path)
        hsexpire = seworker.get_pkl(os.path.join(part_path,
                                                 HSEXPIRE_FILE))
        self.assertEquals(len(hsexpire.keys()), 1)
        self.assertEquals(len(expired_suffixes), 1)

    def test_update_expired_suffix(self):
        device = self.device_list[0]
        part_path = self.part_path_all[device][0]
        disk_file = self.save_object(100, device, part_path, 'a', 'c', 'o')
        suffixes = [s for s in os.listdir(part_path) if len(s) == 3]

        seworker = xauditor.SuffixExpireWorker(self.conf)
        seworker.update_expired_suffix(suffixes, part_path)
        hsexpire = seworker.get_pkl(os.path.join(part_path,
                                                 HSEXPIRE_FILE))
        self.assertEquals(len(suffixes), len(hsexpire.keys()))

    def test_object_xaudit_check_partition(self):
        device = self.device_list[0]
        part_path = self.part_path_all[device][0]

        seworker = xauditor.SuffixExpireWorker(self.conf)

        '''
        Empty parition
        '''
        seworker.check_partition(part_path)

        '''
        One suffix parition
        '''
        disk_file = self.save_object(100, device, part_path, 'a', 'c', 'o')
        object_replicator.get_hashes(part_path, do_listdir=True)
        seworker.check_partition(part_path)

        '''
        An Expiration is happened.
        '''
        time.sleep(int(self.conf.get('expire_age')) + 1)
        seworker.check_partition(part_path)

        '''
        No exist partition dir
        '''
        seworker.check_partition("%s_noexist" % part_path)

    def test_object_xaudit_check_all_partitions(self):
        device = self.device_list[1]
        objects_path = self.objects_path_all[device]
        seworker = xauditor.SuffixExpireWorker(self.conf)

        for pp in self.part_path_all[device]:
            disk_file = self.save_object(100, device, pp, 'a', 'c', 'o')

        for pp in self.part_path_all[device]:
            object_replicator.get_hashes(pp, do_listdir=True)

        seworker.check_all_partitions(objects_path)
        for pp in self.part_path_all[device]:
            hf = os.path.join(pp, HASH_FILE)
            hsef = os.path.join(pp, HSEXPIRE_FILE)
            self.assertEqual(os.path.isfile(hf), True)
            self.assertEqual(os.path.isfile(hsef), True)

    def test_object_xaudit_check_all_partitions_2(self):
        def mock_is_dir1(path):
            return False

        def mock_is_dir2(path):
            raise Exception("mock_is_dir2")

        @contextmanager
        def _dummy_isdir(mock_is_dir):
            original = os.path.isdir
            os.path.isdir = mock_is_dir
            yield
            os.path.isdir = original

        device = self.device_list[1]
        objects_path = self.objects_path_all[device]
        seworker = xauditor.SuffixExpireWorker(self.conf)
        with _dummy_isdir(mock_is_dir1):
            seworker.check_all_partitions(objects_path)

        with _dummy_isdir(mock_is_dir2):
            seworker.check_all_partitions(objects_path)

    def test_object_xaudit_check_all_devices(self):
        class SuffixExpireWorkerMock(object):
            datadir_path_list = []

            def mock_check_all_partitions(self, datadir_path):
                self.datadir_path_list.append(datadir_path)

        class SuffixExpireWorkerMock2(object):
            is_called = False

            def mock_check_all_partitions(self, datadir_path):
                self.is_called = True
                raise Exception("Error")

        @contextmanager
        def _mock_suffix_expire_worker(mock):
            original = SuffixExpireWorker.check_all_partitions
            SuffixExpireWorker.check_all_partitions \
                = mock.mock_check_all_partitions
            yield
            SuffixExpireWorker.check_all_partitions = original

        seworker = xauditor.SuffixExpireWorker(self.conf)
        my_mock = SuffixExpireWorkerMock()

        with _mock_suffix_expire_worker(my_mock):
            seworker.mount_check = True
            seworker.check_all_devices()
            self.assertEqual(len(my_mock.datadir_path_list), 0)

            my_mock.datadir_path_list = []
            seworker.mount_check = False
            seworker.check_all_devices()
            self.assertEqual(len(my_mock.datadir_path_list), 2)

        my_mock2 = SuffixExpireWorkerMock2()
        with _mock_suffix_expire_worker(my_mock2):
            seworker.mount_check = False
            seworker.check_all_devices()
            self.assertEqual(my_mock2.is_called, True)

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
            called_run_once_exception = False

            def mock_run_once(self, *args, **kwargs):
                self.check_args = args
                self.check_kwargs = kwargs

            def mock_run_once_exception(self, *args, **kwargs):
                self.called_run_once_exception = True
                raise Exception("run_once_error")

            def mock_sleep(self):
                raise StopForever('stop')

        my_xauditor = xauditor.ObjectXAuditor(dict(devices=self.devices,
                                                   mount_check='false'))
        mocker = ObjectXAuditorMock()
        try:
            my_xauditor.run_once = mocker.mock_run_once
            my_xauditor._sleep = mocker.mock_sleep
            self.assertRaises(StopForever, my_xauditor.run_forever)
            self.assertEquals(mocker.check_args, ())
            self.assertEquals(mocker.check_kwargs['mode'], 'forever')

            my_xauditor.run_once = mocker.mock_run_once_exception
            self.assertRaises(StopForever, my_xauditor.run_forever)
            self.assertEquals(mocker.called_run_once_exception, True)

        finally:
            pass

    def test_sleep(self):
        my_xauditor = xauditor.ObjectXAuditor(dict(devices=self.devices,
                                                   mount_check='false',
                                                   sleep_time='2'))
        my_xauditor._sleep()


if __name__ == '__main__':
    unittest.main()
