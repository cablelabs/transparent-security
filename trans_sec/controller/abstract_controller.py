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

from trans_sec.exceptions import NotFoundError

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
        self.load_p4 = load_p4
        self.switches = list()

    def start(self):
        logger.info('Adding helpers to switch of type - [%s]',
                    self.switch_type)
        self.__add_helpers()

        logger.info('Switch forwarding start')
        self.__switch_forwarding()
        for switch in self.switches:
            logger.info('Starting digest listeners on device [%s]',
                        switch.grpc_addr)
            switch.add_switch_id(switch.device_id)
            switch.start_digest_listeners()

    def stop(self):
        for switch in self.switches:
            logger.info('Stopping digest listeners on device [%s]',
                        switch.grpc_addr)
            switch.stop_digest_listeners()

    def make_rules(self, sw, north_facing_links, south_facing_links,
                   add_di):
        """
        Abstract method
        :param sw: switch object
        :param north_facing_links: northbound links
        :param south_facing_links: southbound links
        :param add_di: populate data_inspection tables when true
        """
        logger.info('Creating rules for switch type - [%s]', self.switch_type)
        for north_link in north_facing_links:
            logger.info('Creating rules for the north link - [%s]', north_link)
            self.make_north_rules(sw, north_link)

        for south_link in south_facing_links:
            logger.info('Creating rules for the south link - [%s]', south_link)
            self.make_south_rules(sw, south_link, add_di)
        logger.debug('Completed creating rules for switch type [%s]',
                     self.switch_type)

    def make_north_rules(self, sw, north_link):
        raise NotImplemented

    def make_south_rules(self, sw, south_link, add_di):
        if south_link.get('south_facing_port'):
            logger.info('Creating south switch rules - [%s]', south_link)
            if self.topo['switches'].get(south_link['south_node']):
                device = self.topo['switches'][south_link['south_node']]
                logger.info(
                    'This: %s connects to south switch: %s on physical '
                    'port %s to physical port %s',
                    sw.name, device['name'],
                    str(south_link.get('south_facing_port')),
                    str(south_link.get('north_facing_port')))
            elif self.topo['hosts'].get(south_link['south_node']) is not None:
                device = self.topo['hosts'][south_link['south_node']]
                logger.info(
                    'This: %s connects to Device: %s on physical '
                    'port %s',
                    sw.name, device['name'],
                    str(south_link.get('south_facing_port')))
            else:
                raise NotFoundError(
                    'make south rules',
                    'South Bound Link for %s, %s does not exist in topology' %
                    (sw.name, south_link.get('south_node')))

            if device is not None and add_di:
                logger.info('Adding inspection to mac [%s] on device [%s]',
                            device['mac'], sw.grpc_addr)
                sw.add_data_inspection(dev_id=device['id'],
                                       dev_mac=device['mac'])
        else:
            logger.info('No south links to install')

    def __add_helpers(self):
        logger.info('Setting up helpers for [%s]', self.switch_type)
        logger.debug('This topology - [%s]', self.topo)
        for name, switch in self.topo['switches'].items():
            logger.info('Setting up helper for - [%s] of type - [%s]',
                        name, switch.get('type'))

            if switch['type'] == self.switch_type:
                if self.platform == 'bmv2':
                    self.__setup_bmv2_helper(name, switch)
                elif self.platform == 'tofino':
                    self.__setup_bmv2_helper(name, switch)

    def make_switch_rules(self, add_di):
        logger.info('Make Rules for controller [%s]', self.switch_type)
        for switch in self.switches:
            north_links, south_links = self.__get_links(switch.name)
            self.make_rules(sw=switch,
                            north_facing_links=north_links,
                            south_facing_links=south_links,
                            add_di=add_di)

    def __switch_forwarding(self):
        logger.info('Forwarding Rules for controller [%s]', self.switch_type)
        for switch in self.switches:
            logger.info('L2 forwarding rules for %s', switch.name)
            hosts_topo = self.topo['hosts']
            logger.debug('Hosts defs - [%s]', hosts_topo)
            switch.write_multicast_entry(hosts_topo)

    def add_attacker(self, attack, host):
        raise NotImplemented

    def remove_attacker(self, attack, host):
        raise NotImplemented

    def __get_links(self, switch_name):
        """
         Build path through Switch
         Southbound Link => Switch => Northbound Link
         Southbound Link give us the keys to tables
         Northbound Link give us the parameters for actions
         Assumptions:
         Gateways:  All southbound links are hosts, a single northbound link is
                    aggregate
         Aggregate: All southbound links are gateways, a single northbound link
                    is core
         Core:  a single southbound aggregate with two northbound links one
                inet host and one AE
        :param switch_name: the name of the switch
        :return:
        """
        logger.info('Retrieving switch links from topology')
        conditions = {'south_node': switch_name}
        north_facing_links = filter(
            lambda item: all((item[k] == v for (k, v) in conditions.items())),
            self.topo['links'])
        conditions = {'north_node': switch_name}
        south_facing_links = filter(
            lambda item: all((item[k] == v for (k, v) in conditions.items())),
            self.topo['links'])

        logger.debug('Links: north - [%s], south - [%s]',
                     north_facing_links, south_facing_links)
        return list(north_facing_links), list(south_facing_links)

    def __setup_bmv2_helper(self, name, switch):
        """
        Initializes self.p4info_helper for BMV2 switches
        :param name: the switch name
        :param switch: the switch object
        """
        logger.info('Adding BMV P4 Info Helper to switch - [%s]', switch)

        new_switch = self.instantiate_switch(self.topo['switches'][name])
        logger.info('New switch info - [%s]', new_switch.sw_info)
        new_switch.master_arbitration_update()

        if self.load_p4:
            device_config = new_switch.build_device_config()
            if device_config:
                new_switch.set_forwarding_pipeline_config(device_config)
            else:
                raise Exception('Forwarding pipeline cannot be configured')
        else:
            logger.warning('Switches should already be configured')

        self.switches.append(new_switch)
        logger.info('Instantiated connection to switch - [%s]', name)

    @abstractmethod
    def instantiate_switch(self, sw_info):
        raise NotImplemented
