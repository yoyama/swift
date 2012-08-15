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

import os
import time
from random import shuffle
import cPickle as pickle

from eventlet import GreenPool, tpool, Timeout, sleep, hubs
from eventlet.green import subprocess
from eventlet.support.greenlets import GreenletExit

from swift.obj import server as object_server
from swift.obj import replicator as object_replicator
from swift.obj.replicator import PICKLE_PROTOCOL, ONE_WEEK, HASH_FILE
from swift.common.utils import lock_path, \
    get_logger, write_pickle, renamer, listdir, TRUE_VALUES
from swift.common.daemon import Daemon

HSEXPIRE_FILE = 'hashes_expire.pkl'


class SuffixExpireWorker(object):
    """
    This worker manages expiration of suffixes in each hashes.pkl.
    Store expiration date to hashes_expire.pkl.
    """

    def __init__(self, conf):
        self.conf = conf
        self.logger = get_logger(conf, log_route='object-xauditor')
        self.devices = conf.get('devices', '/srv/node')
        self.mount_check = conf.get('mount_check', 'true').lower() in \
            TRUE_VALUES
        self.expire_age = int(conf.get('expire_age', ONE_WEEK))
        self.logger.debug("expire_age :%d" % self.expire_age)

    def check_all_devices(self, datadir=object_server.DATADIR):
        """
        Check expiration of suffix in hashes.pkl on all devices.

        :params datadir: the name of object data dir. default is 'objects'
        """
        device_dir = listdir(self.devices)
        shuffle(device_dir)
        for device in device_dir:
            try:
                if self.mount_check and not \
                        os.path.ismount(os.path.join(self.devices, device)):
                    self.logger.info('Skipping %s as it is not mounted'
                                     % device)
                    continue

                datadir_path = os.path.join(self.devices, device, datadir)
                self.logger.info("try to check device: %s" % datadir_path)
                self.check_all_partitions(datadir_path)
                self.logger.info("end check device: %s" % datadir_path)
            except Exception, e:
                self.logger.error("check_all_devices():%s" % e)

    def check_all_partitions(self, datadir_path):
        """
        Check expiration of suffix in hashes.pkl on all partitions
        in one devcie.

        :params datadir_path: the path of the device to check.
        """
        part_list = os.listdir(datadir_path)
        part_list_len = len(part_list)
        progress_n = part_list_len / 10

        self.logger.info(" num of partitions: %d" % part_list_len)

        cnt = 0
        for partition in part_list:
            try:
                part_path = os.path.join(datadir_path, partition)
                if(not os.path.isdir(part_path)):
                    self.logger.debug(" %s is not dir. skipped." % part_path)
                    continue
                self.check_partition(part_path)
                cnt += 1
                if(progress_n > 0 and cnt % progress_n == 0):
                    self.logger.info("%d partitions processed" % cnt)

            except Exception, e:
                self.logger.error("check_all_partitions(): %s" % e)
        self.logger.info("finished %d partitions" % cnt)

    def check_partition(self, part_path):
        """
        Check expiration of suffix in hashes.pkl on the partition.

        :params part_path: the path of the partition to check.
        """
        expired_suffixes = self.update_hsexpire_pkl(part_path)
        if(expired_suffixes):
            self.logger.debug("expired: %s in %s" % (expired_suffixes,
                                                     part_path))
            self.update_expired_suffix(expired_suffixes, part_path)

    def get_pkl(self, hash_path):
        hashes = {}
        try:
            with open(hash_path, 'rb') as fph:
                hashes = pickle.load(fph)
        except IOError, ioe:
            pass
        except Exception, e:
            self.logger.error("get_pkl() %s" % e)
        return hashes

    def update_hsexpire_pkl(self, part_path):
        """
        Compare hashes.pkl and hashes_expire.pkl and
        updates hashes_expire.pkl.
        Add new suffixes with expiration date.
        Delete obsolete suffixes.
        Return expired suffixes.

        :params part_path: The path to the partition
        :returns: a list of expired suffixes
        """
        hashes_path = os.path.join(part_path, HASH_FILE)
        hsexpire_path = os.path.join(part_path, HSEXPIRE_FILE)

        with lock_path(part_path):
            hashes = self.get_pkl(hashes_path)
            hsexpire = self.get_pkl(hsexpire_path)

            hashes_key_all = set(hashes.keys())
            hsexpire_key_all = set(hsexpire.keys())

            now_date = time.time()
            new_expire_date = now_date + self.expire_age

            removed_keys = hsexpire_key_all.difference(hashes_key_all)
            added_keys = hashes_key_all.difference(hsexpire_key_all)
            intersect_keys = hashes_key_all.intersection(hsexpire_key_all)
            for k in removed_keys:
                del hsexpire[k]
                self.logger.debug("deleted %s in %s" % (k, part_path))
            for k in added_keys:
                hsexpire[k] = new_expire_date
                self.logger.debug("added %s:%d in %s" % (k, new_expire_date,
                                                         part_path))
            if(len(removed_keys) + len(added_keys) > 0):
                write_pickle(hsexpire, hsexpire_path, part_path,
                             PICKLE_PROTOCOL)

            expired_keys = []
            for k in intersect_keys:
                if(hsexpire[k] < now_date):
                    expired_keys.append(k)

            return expired_keys

    def update_expired_suffix(self, suffixes, part_path):
        """
        Recalculate the hash value of suffixes which are expired.
        Then set new expiration date to hashes_expire.pkl
        """
        hsexpire_path = os.path.join(part_path, HSEXPIRE_FILE)

        object_replicator.get_hashes(part_path, recalculate=suffixes)

        with lock_path(part_path):
            hsexpire = self.get_pkl(hsexpire_path)

            now_date = time.time()
            new_expire_date = now_date + self.expire_age

            for s in suffixes:
                hsexpire[s] = new_expire_date

            write_pickle(hsexpire, hsexpire_path, part_path, PICKLE_PROTOCOL)


class ObjectXAuditor(Daemon):
    """
    Exteneded auditor daemon which checks suffix expiration and
    recalculates hash values.

    """

    def __init__(self, conf, **options):
        self.conf = conf
        self.logger = get_logger(conf, log_route='object-xauditor')
        self.sleep_time = int(conf.get("sleep_time", 3600))
        self.logger.debug("sleep_time :%d" % self.sleep_time)

    def _sleep(self):
        time.sleep(self.sleep_time)

    def run_forever(self, *args, **kwargs):
        """Run the object audit until stopped."""
        kwargs = {'mode': 'forever'}
        while True:
            try:
                self.run_once(**kwargs)
            except (Exception, Timeout):
                self.logger.exception(_('ERROR auditing'))
            self._sleep()

    def run_once(self, *args, **kwargs):
        """Run the object audit once."""
        mode = kwargs.get('mode', 'once')
        worker = SuffixExpireWorker(self.conf)
        worker.check_all_devices(datadir=object_server.DATADIR)
