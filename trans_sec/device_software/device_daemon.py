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
from datetime import datetime
from pkg_resources import resource_filename
from time import sleep

from dateutil import parser

from trans_sec.device_software.abstract_daemon import AbstractDaemon


class HeartbeatDaemon(AbstractDaemon):
    """
    Starts and controls an daemon running on a device within to send some UDP
    packets
    """

    def start(self):
        # wait a few seconds to start
        super(self.__class__, self).start()
        sleep(5)
        self.logger.info('Starting HeartbeatDaemon on device - [%s]',
                         self.mn_device.name)
        self.__setup_device()
        self.run()
        self.logger.info('Starting thread for %s', self.mn_device)

    def __setup_device(self):
        dev_prog = resource_filename(
            'trans_sec.device_software', 'send_udp.py')
        cmd = 'python %s' % dev_prog
        cmd += ' --duration=%d' % self.device_config.get('duration')
        cmd += ' --interval=%f' % self.device_config.get('interval')
        cmd += ' --delay=%d' % self.device_config.get('delay')
        cmd += ' --destination=%s' % self.device_config.get('destination')
        cmd += ' --port=%d' % self.device_config.get('port')
        cmd += ' --msg=%s' % self.device_config.get('msg')
        cmd += ' --interface=%s' % self.device_config.get('interface')
        cmd += ' --loglevel=%s' % self.device_config.get('loglevel')
        cmd += ' --logfile={}/{}'.format(self.device_log_dir,
                                         self.device_config.get('logfile'))
        cmd += ' --switch_ethernet=%s' % self.device_config.get(
            'switch_ethernet')
        self.logger.debug(cmd)
        self.cmd = cmd


class SniffAndLogDaemon(AbstractDaemon):
    """
    Starts and controls an daemon running on a device within to send some UDP
    packets
    """
    def start(self):
        super(self.__class__, self).start()
        sleep(5)
        self.logger.info('Starting SniffAndLogDaemon on device - [%s]',
                         self.mn_device.name)
        self.__setup_device()
        self.run()

    def __setup_device(self):
        iface = self.device_config.get('iface')

        if iface:
            dev_prog = resource_filename(
                'trans_sec.device_software', 'receive_udp.py')
            cmd = 'python %s' % dev_prog
            cmd += ' --iface={}'.format(iface)
            cmd += ' --logfile={}/{}'.format(self.device_log_dir,
                                             self.device_config.get('logfile'))
            self.logger.debug(cmd)
            self.cmd = cmd
        else:
            raise Exception('iface not configured')


class AttackDaemon(AbstractDaemon):
    """
    Starts and controls an attack daemon running on a device within
    a locally running mininet
    """
    def __init__(self, mn_device, device_config, log_file,
                 device_log_dir, level):
        super(self.__class__, self).__init__(
            mn_device, device_config, log_file, device_log_dir, level)

        self.active = False

    def stop(self):
        self.active = False
        super(self.__class__, self).stop()

    def start(self):
        self.logger.info('Daemon [{}]'.format(self.mn_device))
        super(self.__class__, self).start()
        self.active = True

        while self.running and self.device_config:
            while not self.active:
                # TODD - Determine proper attack logic here
                attack = None
                if attack:
                    # TODO - Determine new mechanism for start/stopping attacks
                    if attack is not None and attack.get('active'):
                        # Check timing
                        if (attack.get('attackEnd') is not None
                                and attack.get('attackStart') is not None):
                            attack_end = parser.parse(attack.get('attackEnd'))
                            attack_start = parser.parse(attack.get(
                                'attackStart'))
                            attack_end = attack_end.replace(tzinfo=None)
                            attack_start = attack_start.replace(tzinfo=None)
                            now = datetime.now()
                            now = now.replace(tzinfo=None)
                            self.logger.error(now)
                            self.logger.error(attack_end)
                            self.logger.error(attack_start)
                            start_offset = (attack_start - now).total_seconds()
                            end_offset = (now - attack_end).total_seconds()
                            # If we are at the start and before the end go
                            if start_offset <= 0 and end_offset <= 0:
                                self.active = True
                                self.__setup_device(attack.get('attackType'),
                                                    attack.get('durationSec'))
                            else:
                                sleep(1)
                else:
                    sleep(1)
            self.run()
        self.logger.info('Thread %s stopped', self.mn_device)

    def __setup_device(self, attack_type, duration):
        if attack_type == 'HULK Attack':
            hulk_script = resource_filename('trans_sec.device_software',
                                            'hulk-attack.sh')
            hulk_python = resource_filename('trans_sec.device_software',
                                            'hulk.py')
            cmd = hulk_script
            cmd += ' %s' % hulk_python
            cmd += ' %s' % self.device_config.get('destination')
            cmd += ' %d' % duration
        else:
            if attack_type == 'SYN Flood':
                dev_prog = resource_filename('trans_sec.device_software',
                                             'syn_flood.py')
            else:
                dev_prog = resource_filename('trans_sec.device_software',
                                             'send_udp.py')
            cmd = 'python %s' % dev_prog
            cmd += ' --duration=%d' % duration
            cmd += ' --interval=%f' % self.device_config.get('interval')
            cmd += ' --delay=%d' % self.device_config.get('delay')
            cmd += ' --destination=%s' % self.device_config.get('destination')
            cmd += ' --port=%d' % self.device_config.get('port')
            cmd += ' --msg=%s' % self.device_config.get('msg')
            cmd += ' --loglevel=%s' % self.device_config.get('loglevel')
            cmd += ' --logfile={}/{}'.format(self.device_log_dir,
                                             self.device_config.get('logfile'))
            if attack_type == 'SYN Flood':
                syn_flood = self.device_config.get('syn_flood')
                cmd += ' --count=%s' % syn_flood.get('count')
            else:
                udp_flood = self.device_config.get('udp_flood')
                cmd += ' --interface=%s' % udp_flood.get('interface')
                cmd += ' --switch_ethernet=%s' % udp_flood.get(
                    'switch_ethernet')
        self.logger.debug(cmd)
        self.cmd = cmd
