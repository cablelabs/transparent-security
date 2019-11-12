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
import logging


class AbstractDaemon(object):
    """
    Abstract superclass for running a daemon on a device
    """
    def __init__(self, mn_device, device_config, log_file, device_log_dir,
                 level):
        self.running = False
        self.cmd = None
        self.logger = logging.getLogger('{}_{}'.format(
            self.__class__.__name__, mn_device.name))
        self.device_log_dir = device_log_dir

        self.mn_device = mn_device
        self.device_config = device_config

        formatter = logging.Formatter(
            '%(levelname)s %(asctime)-15s %(filename)s %(lineno)d %(message)s')
        fh = logging.FileHandler(log_file)
        fh.setLevel(level)
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)

    def start(self):
        self.running = True

    def stop(self):
        self.running = False
        self.logger.info('Thread %s stopping' % self.mn_device.name)

    def run(self):
        logging.info('Executing command [%s] on device for class [%s]',
                     self.cmd, self.__class__.__name__)
        if self.cmd:
            self.mn_device.cmd(self.cmd)
        else:
            raise Exception('Command is None')
