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
import trans_sec.consts
from trans_sec.controller.abstract_controller import AbstractController

logger = getLogger('gateway_controller')


class GatewayController(AbstractController):
    """
    Implementation of the controller for a switch running the gateway.p4
    program
    """
    def __init__(self, platform, p4_build_out, topo, log_dir, load_p4=True):
        super(self.__class__, self).__init__(
            platform, p4_build_out, topo, 'gateway',
            ['TpsGwIngress.forwardedPackets', 'TpsGwIngress.droppedPackets'],
            log_dir, load_p4, 'TpsGwIngress')

    def make_rules(self, sw, sw_info, north_facing_links, south_facing_links,
                   add_di):
        """
        Overrides the abstract method from super
        :param sw: switch object
        :param sw_info: switch info object
        :param north_facing_links: northbound links
        :param south_facing_links: southbound links
        :param add_di: when True inserts into the data_inspection_t table
        """
        sw_link = north_facing_links[0]
        if len(self.topo['switches']) == 1:
            north_switch = self.topo['hosts'][sw_link['north_node']]
        else:
            north_switch = self.topo['switches'][sw_link['north_node']]
        logger.info('Gateway: ' + sw_info['name'] +
                    ' connects northbound to northbound switch: ' +
                    north_switch.get('name') +
                    ' on physical port ' +
                    str(sw_link.get('north_facing_port')) +
                    ' to physical port ' +
                    str(sw_link.get('south_facing_port')))

        for device_link in south_facing_links:
            device = self.topo['hosts'].get(device_link['south_node'])
            logger.info('Gateway: ' + sw_info['name'] +
                        ' connects to Device: ' + device['name'] +
                        ' on physical port ' +
                        str(device_link.get('south_facing_port')) +
                        ' to IP ' + device.get('ip') +
                        ':' + str(device.get('ip_port')))

            if add_di:
                # Northbound Traffic Inspection for IPv4
                action_params = {
                        'device': device['id'],
                        'switch_id': sw_info['id']
                }
                table_entry = self.p4info_helper.build_table_entry(
                    table_name='{}.data_inspection_t'.format(self.p4_ingress),
                    match_fields={
                        'hdr.ethernet.src_mac': device['mac'],
                        'hdr.ethernet.etherType': trans_sec.consts.IPV4_TYPE
                    },
                    action_name='{}.data_inspect_packet_ipv4'.format(
                        self.p4_ingress),
                    action_params=action_params)
                sw.write_table_entry(table_entry)

                # Northbound Traffic Inspection for IPv6
                action_params = {
                        'device': device['id'],
                        'switch_id': sw_info['id']
                }
                table_entry = self.p4info_helper.build_table_entry(
                    table_name='{}.data_inspection_t'.format(self.p4_ingress),
                    match_fields={
                        'hdr.ethernet.src_mac': device['mac'],
                        'hdr.ethernet.etherType': trans_sec.consts.IPV6_TYPE
                    },
                    action_name='{}.data_inspect_packet_ipv6'.format(
                        self.p4_ingress),
                    action_params=action_params)
                sw.write_table_entry(table_entry)

                logger.info(
                    'Installed Northbound Packet Inspection for device with'
                    ' MAC - [%s] with action params - [%s]',
                    device.get('mac'), action_params)
        if len(self.topo['switches']) == 1:
            inet = self.topo['hosts']['host2']
        else:
            inet = self.topo['hosts']['inet']
        # Add entry for forwarding IPv6 packets
        table_entry = self.p4info_helper.build_table_entry(
            table_name='{}.data_forward_ipv6_t'.format(self.p4_ingress),
            match_fields={
                'hdr.ipv6.dstAddr': (inet['ipv6'], 128)
            },
            action_name='{}.data_forward'.format(self.p4_ingress),
            action_params={
                'dstAddr': north_switch['mac'],
                'port': sw_link['north_facing_port']
            })
        sw.write_table_entry(table_entry)

    def set_multicast_group(self, sw, sw_info):
        mc_group_id = 1

        # TODO/FIXME - Need to add logic to parse the topology to determine
        #     egress ports being used on the switch.
        if len(self.topo['switches']) == 1:
            replicas = [{'egress_port': '1', 'instance': '1'},
                        {'egress_port': '2', 'instance': '1'}]
        else:
            if sw_info['name'] == 'gateway1':
                replicas = [{'egress_port': '1', 'instance': '1'},
                            {'egress_port': '2', 'instance': '1'},
                            {'egress_port': '3', 'instance': '1'},
                            {'egress_port': '4', 'instance': '1'}]
            else:
                replicas = [{'egress_port': '1', 'instance': '1'},
                            {'egress_port': '2', 'instance': '1'},
                            {'egress_port': '3', 'instance': '1'}]

        multicast_entry = self.p4info_helper.build_multicast_group_entry(
            mc_group_id, replicas)
        logger.info('Build Multicast Entry: %s', multicast_entry)
        sw.write_multicast_entry(multicast_entry)
        table_entry = self.p4info_helper.build_table_entry(
            table_name='{}.arp_flood_t'.format(self.p4_ingress),
            match_fields={'hdr.ethernet.dst_mac': 'ff:ff:ff:ff:ff:ff'},
            action_name='{}.arp_flood'.format(self.p4_ingress),
            action_params={
                'srcAddr': sw_info['mac']
            })
        sw.write_table_entry(table_entry)

    def add_data_forward(self, sw, sw_info, src_ip, mac, port):
        logger.info("Gateway - Check if %s belongs to: %s", src_ip,
                    self.known_devices)
        if src_ip not in self.known_devices:
            logger.info("Adding unique table entry on %s for %s",
                        sw_info['name'], src_ip)
            table_entry = self.p4info_helper.build_table_entry(
                table_name='{}.data_forward_ipv4_t'.format(self.p4_ingress),
                match_fields={
                    'hdr.ipv4.dstAddr': (src_ip, 32)
                },
                action_name='{}.data_forward'.format(self.p4_ingress),
                action_params={
                    'dstAddr': mac,
                    'port': port
                })
            sw.write_table_entry(table_entry)
            table_entry = self.p4info_helper.build_table_entry(
                table_name='{}.arp_reply_t'.format(self.p4_ingress),
                match_fields={'hdr.arp.dstAddr': (src_ip, 32)},
                action_name='{}.arp_reply'.format(self.p4_ingress),
                action_params={
                    'srcAddr': sw_info['mac'],
                    'dstAddr': mac,
                    'port': port
                })
            sw.write_table_entry(table_entry)
        self.known_devices.add(src_ip)
