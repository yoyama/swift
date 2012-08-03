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
from shutil import rmtree
from hashlib import md5
from tempfile import mkdtemp
from test.unit import FakeLogger
from swift.obj import auditor, auditor2
from swift.obj import server as object_server
from swift.obj.server import DiskFile, write_metadata, DATADIR
from swift.obj import replicator as object_replicator
from swift.obj.replicator import PICKLE_PROTOCOL, ONE_WEEK, HASH_FILE, \
    invalidate_hash
from swift.obj.auditor2 import HSEXPIRE_FILE
from swift.common.utils import hash_path, mkdirs, normalize_timestamp, \
    renamer, storage_directory
from swift.common.exceptions import AuditException


class TestAuditor2(unittest.TestCase):

    def setUp(self):
        print "setUp() called"
        self.testdir = os.path.join(mkdtemp(), 'tmp_test_object_auditor2')
        self.devices = os.path.join(self.testdir, 'node')
        self.logger = FakeLogger()
        rmtree(self.testdir, ignore_errors=1)
        mkdirs(os.path.join(self.devices, 'sda'))
        self.objects = os.path.join(self.devices, 'sda', 'objects')

        os.mkdir(os.path.join(self.devices, 'sdb'))
        self.objects_2 = os.path.join(self.devices, 'sdb', 'objects')

        os.mkdir(self.objects)
        self.parts = {}
        for part in ['0', '1', '2', '3']:
            self.parts[part] = os.path.join(self.objects, part)
            os.mkdir(os.path.join(self.objects, part))

        self.conf = dict(
            devices=self.devices,
            mount_check='false',
            expire_age = '2')
        self.disk_file = self.save_object(1024, 'sda', '0', 'a', 'c', 'o')

        self.part_path = os.path.join(self.disk_file.device_path, DATADIR, '0')
        self.suffixes = [s for s in os.listdir(self.part_path) if len(s) == 3 ]
        print self.part_path
        print self.suffixes

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
        #rmtree(os.path.dirname(self.testdir), ignore_errors=1)
        unit.xattr_data = {}

    def test_object_audit2_get_pkl(self):
        self.seworker = auditor2.SuffixExpireWorker(self.conf)
        hashes = self.seworker.get_pkl(os.path.join(self.part_path, HASH_FILE))
        self.assertEquals(len(hashes.keys()), 0)

        object_replicator.get_hashes(self.part_path, recalculate=self.suffixes)
        hashes = self.seworker.get_pkl(os.path.join(self.part_path, HASH_FILE))
        self.assertEquals(len(hashes.keys()), 1)


    def test_object_audit2_update_hsexpire_pkl(self):
        self.seworker = auditor2.SuffixExpireWorker(self.conf)

        '''
        No hashes.pkl and expire_hashes file.
        '''
        suffixes = self.seworker.update_hsexpire_pkl(self.part_path)
        hsexpire = self.seworker.get_pkl(os.path.join(self.part_path, HSEXPIRE_FILE))
        self.assertEquals(len(hsexpire.keys()), 0)
        self.assertEquals(len(suffixes), 0)


        '''
        a suffix in hashes.pkl file.
        '''
        object_replicator.get_hashes(self.part_path, recalculate=self.suffixes)
        suffixes = self.seworker.update_hsexpire_pkl(self.part_path)
        hsexpire = self.seworker.get_pkl(os.path.join(self.part_path, HSEXPIRE_FILE))
        self.assertEquals(len(hsexpire.keys()), 1)
        self.assertEquals(len(suffixes), 0)


        '''
        a suffix added. hashes.pkl and expire_hash.pkl exist.
        '''
        for i in range(0,10):
            disk_file2 = self.save_object(1024, 'sda', '0', 'a', 'c', 'obj%d' % i)
            if(self.disk_file.datadir[-3:] != disk_file2.datadir[-3:]):
                break
        object_replicator.get_hashes(self.part_path, do_listdir=True)
        suffixes = self.seworker.update_hsexpire_pkl(self.part_path)
        hsexpire = self.seworker.get_pkl(os.path.join(self.part_path, HSEXPIRE_FILE))
        self.assertEquals(len(hsexpire.keys()), 2)
        self.assertEquals(len(suffixes), 0)
        
        

        '''
        a suffix removed
        '''
        for s in self.suffixes:
            rmtree(os.path.join(self.part_path, s))
        object_replicator.get_hashes(self.part_path, recalculate=self.suffixes)
        suffixes = self.seworker.update_hsexpire_pkl(self.part_path)
        hsexpire = self.seworker.get_pkl(os.path.join(self.part_path, HSEXPIRE_FILE))
        self.assertEquals(len(hsexpire.keys()), 1)
        self.assertEquals(len(suffixes), 0)

        '''
        a suffix expired
        '''
        time.sleep(int(self.conf.get('expire_age')) + 1 )
        suffixes = self.seworker.update_hsexpire_pkl(self.part_path)
        hsexpire = self.seworker.get_pkl(os.path.join(self.part_path, HSEXPIRE_FILE))
        self.assertEquals(len(hsexpire.keys()), 1)
        self.assertEquals(len(suffixes), 1)
        

    def test_object_audit2_check_partition(self):
        self.seworker = auditor2.SuffixExpireWorker(self.conf)
        self.assertEquals(True, False)
        
        
        


    def test_run_forever(self):

        class StopForever(Exception):
            pass

        class ObjectAuditor2Mock(object):
            check_args = ()
            check_kwargs = {}

            def mock_run(self, *args, **kwargs):
                self.check_args = args
                self.check_kwargs = kwargs

            def mock_sleep(self):
                raise StopForever('stop')


        my_auditor2 = auditor2.ObjectAuditor2(dict(devices=self.devices,
                                                mount_check='false'))
                                                
        mocker = ObjectAuditor2Mock()
        my_auditor2.run_once = mocker.mock_run
        my_auditor2._sleep = mocker.mock_sleep
        try:
            self.assertRaises(StopForever,
                              my_auditor2.run_forever)

            self.assertRaises(StopForever, my_auditor2.run_forever)
            self.assertEquals(mocker.check_args, ())

            self.assertRaises(StopForever, my_auditor2.run_forever)

        finally:
            pass

if __name__ == '__main__':
    unittest.main()
