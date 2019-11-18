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

from trans_sec.device_software.device_daemon import SniffAndLogDaemon, \
    HeartbeatDaemon, AttackDaemon

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
            # if self.mininet.get(host_name):
            for dev_conf in dev_confs:
                daemon = self.__create_daemon(host_name, dev_conf)
                if daemon:
                    self.daemons.append(self.__create_daemon(
                        host_name, dev_conf))

        for daemon in self.daemons:
            logger.info('Starting Daemon for %s', daemon.mn_device.name)
            t1 = threading.Thread(target=daemon.start, args=())
            t1.start()
            self.threads.append(t1)

    def stop(self):
        for daemon in self.daemons:
            daemon.stop()

    def __create_daemon(self, host_name, dev_conf):
        """
        Instantiates the configured daemon object
        """
        logger.info('Creating daemon on %s with conf %s', host_name, dev_conf)
        daemon_type = dev_conf.get('daemon')
        mn_device = None
        for device in self.mininet.hosts:
            if device.name == host_name:
                mn_device = device

        if daemon_type and mn_device:
            device_log_file = '{}/device_{}_{}.log'.format(
                self.log_dir, daemon_type, host_name)
            if daemon_type == 'attack':
                logger.info(
                    'Creating attack daemon for [%s] and log file [%s]',
                    host_name, device_log_file)
                return AttackDaemon(
                    mn_device=mn_device,
                    device_config=dev_conf,
                    log_file=device_log_file,
                    device_log_dir=self.log_dir,
                    level=logging.DEBUG)

            elif daemon_type == 'heartbeat':
                logger.info(
                    'Creating heartbeat daemon for [%s] and log file [%s]',
                    host_name, device_log_file)
                return HeartbeatDaemon(
                    mn_device=mn_device,
                    device_config=dev_conf,
                    log_file=device_log_file,
                    device_log_dir=self.log_dir,
                    level=logging.DEBUG)

            elif daemon_type == 'sniff_and_log':
                logger.info(
                    'Creating sniff and log daemon for [%s] and log file [%s]',
                    host_name, device_log_file)
                return SniffAndLogDaemon(
                    mn_device=mn_device,
                    device_config=dev_conf,
                    log_file=device_log_file,
                    device_log_dir=self.log_dir,
                    level=logging.DEBUG)
