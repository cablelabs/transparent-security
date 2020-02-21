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
from logging import getLogger

from trans_sec.p4runtime_lib import bmv2, helper, tofino

logger = getLogger('abstract_controller')


class AbstractController(object):
    def __init__(self, platform, p4_build_out, topo, switch_type, counters,
                 log_dir, load_p4, p4_processing):
        """
        Constructor
        :param platform: the platform on which the switches are running
                         (bmv2|tofino)
        :param p4_build_out: the build artifact directory
        :param topo: the topology config dictionary
        :param switch_type: the type of switch (aggregate|core|gateway)
        :param counters:
        :param log_dir: the directory to which to write the log entries
        :param load_p4: when True, the forwarding pipeline configuration will
                        be sent to the switch
        """
        self.platform = platform
        self.p4_bin_dir = p4_build_out
        self.topo = topo
        self.counters = counters
        self.switch_type = switch_type
        self.log_dir = log_dir
        self.load_p4 = load_p4
        self.switches = list()
        self.p4_processing = p4_processing

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

    def make_rules(self, sw, sw_info, north_facing_links, south_facing_links):
        """
        Abstract method
        :param sw: switch object
        :param sw_info: switch info object
        :param north_facing_links: northbound links
        :param south_facing_links: southbound links
        """
        logger.info('Creating rules for switch type - [%s]', self.switch_type)
        for north_link in north_facing_links:
            logger.info('Creating rules for the north link - [%s]', north_link)
            self.make_north_rules(sw, sw_info, north_link)

        for south_link in south_facing_links:
            logger.info('Creating rules for the south link - [%s]', south_link)
            self.make_south_rules(sw, sw_info, south_link)

    def make_north_rules(self, sw, sw_info, north_link):
        raise NotImplemented

    def make_south_rules(self, sw, sw_info, south_link):
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

            if device is not None:
                self.add_data_inspection(sw, device, sw_info)
        else:
            logger.info('No south links to install')

    def add_data_inspection(self, sw, device, sw_info):
        pass

    def __add_helpers(self):
        logger.info('Setting up helpers')
        for name, switch in self.topo['switches'].items():
            logger.info('Setting up helper for - [%s] of type - [%s]',
                        name, switch.get('type'))
            if switch['type'] == self.switch_type:
                if self.platform == 'bmv2':
                    self.__setup_bmv2_helper(name, switch)
                elif self.platform == 'tofino':
                    self.__setup_tofino_helper(name, switch)

    def reset_all_counters(self, packet_telemetry):
        logger.info('Resetting counters')
        for switch_obj in self.switches:
            switch = packet_telemetry.get_switch_by_name(switch_obj.name)
            devices = packet_telemetry.get_devices(switch.get('children'))
            for device in devices:
                for counter in self.counters:
                    logger.debug('Resetting counter for device [%s]',
                                 device.get('device_id'))
                    switch_obj.reset_counters(
                        self.p4info_helper.get_counters_id(counter),
                        device['device_id'])

    def update_all_counters(self, packet_telemetry):
        logger.info('Updating counters for all switches')
        counter_ids = list()
        for counter in self.counters:
            counter_ids.append(self.p4info_helper.get_counters_id(counter))

        for this_switch in self.switches:
            switch = packet_telemetry.get_switch_by_name(this_switch.name)
            if switch is not None:
                self.__update_counters(
                    this_switch, counter_ids, packet_telemetry)

    @staticmethod
    def __update_counters(this_switch, counter_ids, packet_telemetry):
        logger.info('Updating counters for %s', this_switch)
        for response in this_switch.read_counters():
            for entity in response.entities:
                counter = entity.counter_entry
                packet_count = counter.data.packet_count
                for counter_id in counter_ids:
                    if entity.counter_entry.counter_id == counter_id:
                        if packet_count > 0:
                            packet_telemetry.update_device(
                                counter.index.index,
                                forwarded=packet_count * 100)
                            logger.info(
                                '%s %s %d: %d packets (%d bytes)' % (
                                    this_switch.name,
                                    'forwardedPackets',
                                    counter.index.index,
                                    counter.data.packet_count,
                                    counter.data.byte_count))

    def make_switch_rules(self):
        logger.info('Make Rules for controller [%s]', self.switch_type)
        for switch in self.switches:
            sw_info, north_links, south_links = self.__get_links(switch.name)
            self.make_rules(sw=switch, sw_info=sw_info,
                            north_facing_links=north_links,
                            south_facing_links=south_links)

    def add_attacker(self, attack, host,
                     drop_action_name='data_drop',
                     drop_table_name='data_drop_t',
                     src_mac_hdr_ref='hdr.ethernet.src_mac',
                     src_addr_hdr_ref='hdr.ipv4.srcAddr',
                     dst_addr_hdr_ref='hdr.ipv4.dstAddr',
                     dst_port_hdr_ref='hdr.udp.dst_port'):

        logger.info('Adding attacker [%s] from host [%s]', attack, host)
        for switch in self.switches:
            table_entry = self.p4info_helper.build_table_entry(
                table_name='{}.{}'.format(self.p4_processing, drop_table_name),
                match_fields={
                    src_mac_hdr_ref: (attack['src_mac']),
                    src_addr_hdr_ref: (attack['src_ip']),
                    dst_addr_hdr_ref: (attack['dst_ip']),
                    dst_port_hdr_ref: (int(attack['dst_port']))
                },
                action_name='{}.{}'.format(self.p4_processing, drop_action_name),
                action_params={
                    'device': host['id']
                })
            logger.debug('Writing table entry [%s]', table_entry)
            switch.write_table_entry(table_entry)

            logger.info('%s Dropping Packets from %s',
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

        new_switch = bmv2.Bmv2SwitchConnection(
            name=name,
            address=switch['grpc'],
            device_id=switch['id'],
            proto_dump_file='{}/{}-switch-controller.log'.format(
                self.log_dir, name))
        new_switch.master_arbitration_update()

        bmv2_json_file_path = "{0}/{1}.json".format(
            self.p4_bin_dir, self.switch_type)
        device_config = new_switch.build_device_config(
            bmv2_json_file_path=bmv2_json_file_path)

        if self.load_p4:
            logger.info('Setting forwarding pipeline config on - [%s]', name)
            new_switch.set_forwarding_pipeline_config(
                self.p4info_helper.p4info, device_config)
        else:
            logger.warn('Switches should already be configured')

        self.switches.append(new_switch)
        logger.info('Instantiated connection to BMV2 switch - [%s]',
                    name)

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
            new_switch.set_forwarding_pipeline_config(
                self.p4info_helper.p4info, device_config)
        else:
            logger.warn('Switch [%s] should already be configured', name)

        self.switches.append(new_switch)
        logger.info('Instantiated connection to Tofino switch - [%s]',
                    self.switch_type, name)
