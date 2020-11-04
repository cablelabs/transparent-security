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
from abc import abstractmethod
from logging import getLogger

logger = getLogger('abstract_controller')


class AbstractController(object):
    def __init__(self, platform, p4_build_out, topo, switch_type, log_dir,
                 load_p4):
        """
        Constructor
        :param platform: the platform on which the switches are running
                         (bmv2|tofino)
        :param p4_build_out: the build artifact directory
        :param topo: the topology config dictionary
        :param switch_type: the type of switch (aggregate|core|gateway)
        :param log_dir: the directory to which to write the log entries
        :param load_p4: when True, the forwarding pipeline configuration will
                        be sent to the switch
        """
        self.platform = platform
        self.p4_bin_dir = p4_build_out
        self.topo = topo
        self.switch_type = switch_type
        self.log_dir = log_dir

        # TODO - Implement loading P4 on TNA
        self.load_p4 = load_p4
        self.switches = list()

    def start(self):
        logger.info('Adding helpers to switch of type - [%s]',
                    self.switch_type)
        self.__setup_switches()

        logger.info('Start switch processes')
        for switch in self.switches:
            logger.info('Starting switch at - [%s]', switch.grpc_addr)
            switch.start()

    def stop(self):
        for switch in self.switches:
            logger.info('Stopping digest listeners on device [%s]',
                        switch.grpc_addr)
            switch.stop_digest_listeners()

    def __setup_switches(self):
        logger.info('Setting up switches for [%s]', self.switch_type)
        logger.debug('This topology - [%s]', self.topo)
        for name, switch in self.topo['switches'].items():
            if self.switch_type == switch['type']:
                logger.info('Setting up helper for - [%s] of type - [%s]',
                            name, switch.get('type'))

                self.__setup_switch(name, switch)

    def __setup_switch(self, name, switch):
        """
        Initializes self.p4info_helper for BMV2 switches
        :param name: the switch name
        :param switch: the switch object
        """
        logger.info('[%s] Setting up switch - [%s]',
                    self.__class__.__name__, switch)

        new_switch = self.instantiate_switch(self.topo['switches'][name])
        logger.info('New switch info - [%s]', new_switch.sw_info)
        self.switches.append(new_switch)
        logger.info('Instantiated connection to switch - [%s]', name)

    @abstractmethod
    def add_attacker(self, attack, host):
        raise NotImplemented

    @abstractmethod
    def remove_attacker(self, attack, host):
        raise NotImplemented

    @abstractmethod
    def instantiate_switch(self, sw_info):
        raise NotImplemented
