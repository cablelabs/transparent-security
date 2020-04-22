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
from time import sleep
from trans_sec.device_software.abstract_daemon import AbstractDaemon


class ForwardingDaemon(AbstractDaemon):
    """
    Starts and controls an daemon running on a device within to send some UDP
    packets
    """

    def start(self):
        # wait a few seconds to start
        super(self.__class__, self).start()
        sleep(5)
        self.logger.info('Starting ForwardingDaemon on device - [%s]',
                         self.mn_device.name)
        self.__setup_device()
        self.run()
        self.logger.info('Starting thread for %s', self.mn_device)

    def __setup_device(self):
        cmd = 'ping %s' % self.device_config.get('destination')
        cmd += ' -c %s' % self.device_config.get('packet_count')
        cmd += ' -I %s' % self.device_config.get('interface')
        cmd += ' -i %s' % self.device_config.get('interval')
        self.logger.info('Ping command run on device %s - [%s]',
                         self.device_name, cmd)
        self.cmd = cmd
