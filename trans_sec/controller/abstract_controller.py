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

import ipaddress

from trans_sec.p4runtime_lib import helper, tofino

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

        if self.platform == 'bmv2':
            p4info_txt = "{0}/{1}.{2}".format(
                self.p4_bin_dir, self.switch_type, 'p4info')
        elif self.platform == 'tofino':
            p4info_txt = "{0}/{1}.{2}".format(
                self.p4_bin_dir, self.switch_type, 'p4info.pb.txt')
        else:
            raise Exception('Switch type - {} is not supported'.format(
                            self.switch_type))
        self.p4info_helper = helper.P4InfoHelper(p4info_txt)

    def start(self):
        logger.info('Adding helpers to switch of type - [%s]',
                    self.switch_type)
        self.__add_helpers()
        self.__switch_forwarding()
        for switch in self.switches:
            switch.start_digest_listeners()

    def stop(self):
        for switch in self.switches:
            switch.stop_digest_listeners()

    def make_rules(self, sw, sw_info, north_facing_links, south_facing_links,
                   add_di):
        """
        Abstract method
        :param sw: switch object
        :param sw_info: switch info object
        :param north_facing_links: northbound links
        :param south_facing_links: southbound links
        :param add_di: populate data_inspection tables when true
        """
        logger.info('Creating rules for switch type - [%s]', self.switch_type)
        for north_link in north_facing_links:
            logger.info('Creating rules for the north link - [%s]', north_link)
            self.make_north_rules(sw, sw_info, north_link)

        for south_link in south_facing_links:
            logger.info('Creating rules for the south link - [%s]', south_link)
            self.make_south_rules(sw, sw_info, south_link, add_di)
        logger.debug('Completed creating rules for switch type [%s]',
                     self.switch_type)

    def make_north_rules(self, sw, sw_info, north_link):
        raise NotImplemented

    def make_south_rules(self, sw, sw_info, south_link, add_di):
        if south_link.get('south_facing_port'):
            logger.info('Creating south switch rules - [%s]', south_link)
            if self.topo['switches'].get(south_link['south_node']):
                device = self.topo['switches'][south_link['south_node']]
                logger.info(
                    'This: %s connects to south switch: %s on physical '
                    'port %s to physical port %s',
                    sw_info['name'], device['name'],
                    str(south_link.get('south_facing_port')),
                    str(south_link.get('north_facing_port')))
            elif self.topo['hosts'].get(south_link['south_node']) is not None:
                device = self.topo['hosts'][south_link['south_node']]
                logger.info(
                    'This: %s connects to Device: %s on physical '
                    'port %s',
                    sw_info['name'], device['name'],
                    str(south_link.get('south_facing_port')))
            else:
                raise StandardError(
                    'South Bound Link for %s, %s does not exist in topology' %
                    (sw.name, south_link.get('south_node')))

            if device is not None and add_di:
                sw.add_data_inspection(device['id'], device['mac'])
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
                    self.__setup_tofino_helper(name, switch)

    def make_switch_rules(self, add_di):
        logger.info('Make Rules for controller [%s]', self.switch_type)
        for switch in self.switches:
            sw_info, north_links, south_links = self.__get_links(switch.name)
            self.make_rules(sw=switch, sw_info=sw_info,
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
        logger.info('Attack received by the controller of type [%s] - [%s]',
                    self.switch_type, attack)
        attack_switch = None
        for switch in self.switches:
            di_match_mac = switch.get_data_inspection_src_mac_keys()
            logger.debug(
                'Data inspection table keys on device [%s] - [%s]',
                switch.sw_info['id'], di_match_mac)
            if attack['src_mac'] in di_match_mac:
                logger.info('Found source switch - [%s]', switch.name)
                attack_switch = switch
        if attack_switch:
            logger.info('Adding an attack [%s] to host [%s] and switch [%s]',
                        attack, host, attack_switch.sw_info['name'])
            ip_addr = ipaddress.ip_address(unicode(attack['src_ip']))
            logger.info('Attack ip addr - [%s]', ip_addr)
            logger.debug('Attack ip addr class - [%s]', ip_addr.__class__)
            if ip_addr.version == 6:
                logger.debug('Attack is IPv6')
                proto_key = 'ipv6'
            else:
                logger.debug('Attack is IPv4')
                proto_key = 'ipv4'

            src_addr_key = 'hdr.{}.srcAddr'.format(proto_key)
            dst_addr_key = 'hdr.{}.dstAddr'.format(proto_key)

            logger.info('Adding the attack to switch - [%s]', attack_switch)
            self.__add_attacker(
                attack_switch, attack, host, src_addr_key, dst_addr_key)

    def __add_attacker(self, switch, attack, host, src_addr_key, dst_addr_key):
        logger.info('Attack requested - [%s]', attack)
        ip_addr = ipaddress.ip_address(unicode(attack['src_ip']))
        logger.info('Attack from ip_addr - [%s]', ip_addr)
        logger.info('Inserting IPv%s Attack', ip_addr.version)
        self.__insert_attack_entry(
            switch, attack, host,
            'data_drop_udp_ipv{}_t'.format(ip_addr.version),
            'data_drop', src_addr_key, dst_addr_key, 'hdr.udp.dst_port')
        self.__insert_attack_entry(
            switch, attack, host,
            'data_drop_tcp_ipv{}_t'.format(ip_addr.version),
            'data_drop', src_addr_key, dst_addr_key, 'hdr.tcp.dst_port')

    @staticmethod
    def __insert_attack_entry(switch, attack, host, table_name,
                              action_name, src_addr_key, dst_addr_key,
                              dst_port_key):
        logger.info('Adding attack [%s] from host [%s]', attack, host['name'])
        src_ip = ipaddress.ip_address(unicode(attack['src_ip']))
        dst_ip = ipaddress.ip_address(unicode(attack['dst_ip']))
        logger.info('Attack src_ip - [%s], dst_ip - [%s]', src_ip, dst_ip)
        # TODO - Add back source IP address as a match field after adding
        #  mitigation at the Aggregate
        switch.insert_p4_table_entry(
            table_name=table_name,
            action_name=action_name,
            match_fields={
                'hdr.ethernet.src_mac': attack['src_mac'],
                dst_addr_key: str(dst_ip.exploded),
                dst_port_key: int(attack['dst_port']),
            },
            action_params={
                'device': host['id']
            },
            ingress_class=True
         )
        logger.info('%s Dropping TCP Packets from %s',
                    switch.name, attack.get('src_ip'))

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
        sw_info = self.topo['switches'][switch_name]
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
        return sw_info, north_facing_links, south_facing_links

    def __setup_bmv2_helper(self, name, switch):
        """
        Initializes self.p4info_helper for BMV2 switches
        :param name: the switch name
        :param switch: the switch object
        """
        logger.info('Adding BMV P4 Info Helper to switch - [%s]', switch)

        new_switch = self.instantiate_switch(self.topo['switches'][name])
        new_switch.master_arbitration_update()

        bmv2_json_file_path = "{0}/{1}.json".format(
            self.p4_bin_dir, self.switch_type)
        device_config = new_switch.build_device_config(
            bmv2_json_file_path=bmv2_json_file_path)

        if self.load_p4:
            logger.info('Setting forwarding pipeline config on - [%s]', name)
            new_switch.set_forwarding_pipeline_config(device_config)
        else:
            logger.warn('Switches should already be configured')

        self.switches.append(new_switch)
        logger.info('Instantiated connection to BMV2 switch - [%s]',
                    name)

    @abstractmethod
    def instantiate_switch(self, sw_info):
        raise NotImplemented

    def __setup_tofino_helper(self, name, switch):
        """
        Creates the Tofino switch connection and loads the P4 program when
        self.load_p4 is True
        :param name: the switch name
        :param switch: the switch dict object from topology
        """
        logger.info('Adding Tofino P4 Info Helper to switch - [%s]', switch)

        new_switch = tofino.TofinoSwitchConnection(
            name=name,
            address=switch['grpc'],
            device_id=switch['id'])
        new_switch.master_arbitration_update()

        bin_path = "{0}/{1}.tofino/pipe/tofino.bin".format(
            self.p4_bin_dir, self.switch_type)
        cxt_json_path = "{0}/{1}.tofino/pipe/context.json".format(
            self.p4_bin_dir, self.switch_type)
        device_config = new_switch.build_device_config(
            prog_name=name,
            bin_path=bin_path,
            cxt_json_path=cxt_json_path)

        logger.info(
            'Loading P4 application to Tofino switch - [%s] with bin - [%s] '
            'and context - [%s]',
            name, bin_path, cxt_json_path)

        if self.load_p4:
            logger.info('Setting forwarding pipeline config on - [%s]', name)
            new_switch.set_forwarding_pipeline_config(device_config)
        else:
            logger.warn('Switch [%s] should already be configured', name)

        self.switches.append(new_switch)
        logger.info('Instantiated connection to Tofino switch - [%s]',
                    self.switch_type, name)
