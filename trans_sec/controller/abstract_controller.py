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

from trans_sec.p4runtime_lib import bmv2, helper

logger = getLogger('abstract_controller')


class AbstractController(object):
    """
    Base controller class for a particular P4 switch implementation
    """

    def __init__(self, p4_build_out, topo, switch_type, counters, log_dir):
        """
        Constructor
        :param p4_build_out:
        :param topo: a dict representing the mininet topology
        :param switch_type:
        :param counters:
        """
        self.p4_bin_dir = p4_build_out
        self.topo = topo
        self.counters = counters
        self.switch_type = switch_type
        self.log_dir = log_dir
        self.switches = []
        self.__add_helpers()

    def make_rules(self, sw, sw_info, north_facing_links, south_facing_links):
        """
        Abstract method
        :param sw: switch object
        :param sw_info: switch info object
        :param north_facing_links: northbound links
        :param south_facing_links: southbound links
        """
        raise NotImplemented

    def __add_helpers(self):
        for name, switch in self.topo.get('switches').items():
            if switch.get('type') == self.switch_type:
                self.__setup_helper(name, switch)

    def __setup_helper(self, name, switch):
        """
        Initializes self.p4info_helper and self.switches list for Mininet
        :param name: the switch name
        :param switch: the switch object
        """
        self.p4info_helper = helper.P4InfoHelper(
            "{0}/{1}.p4info".format(self.p4_bin_dir, self.switch_type))
        new_switch = bmv2.Bmv2SwitchConnection(
            name=name,
            address=switch.get('grpc'),
            device_id=switch.get('id'),
            proto_dump_file='{}/{}-switch-controller.log'.format(
                self.log_dir, name))
        new_switch.master_arbitration_update()

        bmv2_json_file_path = "{0}/{1}.json".format(
            self.p4_bin_dir, self.switch_type)
        logger.info('Setting forward pipeline config with bmv2 json - [%s]',
                    bmv2_json_file_path)
        new_switch.set_forwarding_pipeline_config(
            p4info=self.p4info_helper.p4info,
            bmv2_json_file_path=bmv2_json_file_path)
        self.switches.append(new_switch)
        logger.info(
            'Installed P4 %s on BMV2 using '
            'SetForwardingPipelineConfig', name)

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
                        device.get('device_id'))

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

    def add_attacker(self, attack, host):
        logger.info('Adding attacker [%s] from host [%s]', attack, host)
        for switch in self.switches:
            table_entry = self.p4info_helper.build_table_entry(
                table_name='MyIngress.data_drop_t',
                match_fields={
                    'hdr.ipv4.srcAddr': attack.get('src_ip'),
                    'hdr.ipv4.dstAddr': attack.get('dst_ip'),
                    'hdr.udp.dst_port': attack.get('dst_port'),
                    'hdr.udp.len': attack.get('packet_size')
                },
                action_name='MyIngress.data_drop',
                action_params={
                    'device': host.get('id')
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
        sw_info = self.topo.get('switches').get(switch_name)
        conditions = {'south_node': switch_name}
        north_facing_links = filter(
            lambda item: all((item[k] == v for (k, v) in conditions.items())),
            self.topo.get('links'))
        conditions = {'north_node': switch_name}
        south_facing_links = filter(
            lambda item: all((item[k] == v for (k, v) in conditions.items())),
            self.topo.get('links'))
        return sw_info, north_facing_links, south_facing_links
