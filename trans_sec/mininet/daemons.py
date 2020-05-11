# Copyright (c) 2019 Cable Television Laboratories, Inc.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# Unit tests for convert.py
import logging
import threading

from trans_sec.device_software.device_daemon import ForwardingDaemon

logger = logging.getLogger('daemons')


class DaemonRunner:

    def __init__(self, mininet, devices_conf, log_dir):

        self.log_dir = log_dir

        self.mininet = mininet
        self.devices_conf = devices_conf
        self.daemons = list()
        self.threads = list()

    def start_daemons(self):
        hosts1 = self.mininet.hosts
        logger.info('Init mininet with hosts %s', hosts1)

        self.mininet.init()
        items = self.mininet.items()
        logger.info('mininet items %s', items)

        hosts2 = self.mininet.hosts
        logger.info('Init mininet with hosts %s', hosts2)

        # Create Mininet host daemons
        for host_name, dev_confs in self.devices_conf.items():
            for dev_conf in dev_confs:
                self.daemons.append(self.__create_daemon(host_name, dev_conf))

        for daemon in self.daemons:
            logger.info('Starting Daemon for %s', daemon.mn_device.name)
            t1 = threading.Thread(target=daemon.start, args=())
            t1.start()
            logger.info('Daemon [%s] started', daemon.mn_device.name)
            self.threads.append(t1)

    def stop(self):
        for daemon in self.daemons:
            daemon.stop()

    def __create_daemon(self, host_name, dev_conf):
        """
        Instantiates the configured daemon object
        """
        logger.info('Creating daemon on %s with conf %s', host_name, dev_conf)
        mn_device = None
        for device in self.mininet.hosts:
            if device.name == host_name:
                mn_device = device

        if mn_device:
            device_log_file = '{}/fwd_daemon_{}.log'.format(
                self.log_dir, host_name)
            logger.info(
                'Creating forwarding daemon for [%s] and log file [%s]',
                host_name, device_log_file)
            return ForwardingDaemon(host_name, mn_device, dev_conf)
