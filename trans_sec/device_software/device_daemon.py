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
from time import sleep

logger = logging.getLogger('device_daemon')


class ForwardingDaemon:
    """
    Starts and controls an daemon running on a device within to send some UDP
    packets
    """

    def __init__(self, device_name, mn_device, device_config):
        self.device_name = device_name
        self.mn_device = mn_device
        self.device_config = device_config

    def start(self):
        # wait a few seconds to start
        sleep(5)
        logger.info('Starting ForwardingDaemon on device - [%s]',
                    self.mn_device.name)
        self.__ping_devices()

    def __ping_devices(self):
        cmd = 'ping %s' % self.device_config.get('destination')
        cmd += ' -c %s' % self.device_config.get('packet_count')
        cmd += ' -I %s' % self.device_config.get('interface')
        cmd += ' -i %s' % self.device_config.get('interval')
        logger.info('Ping command run on device [%s] - [%s]',
                    self.device_name, cmd)
        self.mn_device.cmd(cmd)
