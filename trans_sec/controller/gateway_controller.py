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
from trans_sec.utils.convert import decode_num, decode_ipv4

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
        self.nat_udp_ports = set()
        self.nat_tcp_ports = set()
        self.tcp_port_count = 1
        self.udp_port_count = 1

    def make_rules(self, sw, sw_info, north_facing_links, south_facing_links):
        """
        Overrides the abstract method from super
        :param sw: switch object
        :param sw_info: switch info object
        :param north_facing_links: northbound links
        :param south_facing_links: southbound links
        """
        if 0 < len(north_facing_links) < 2:
            sw_link = north_facing_links[0]
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
        else:
            logger.error('Wrong number of nb switches on gateway')
            logger.error(sw_info.get('name'))

    def set_multicast_group(self, sw, sw_info):
        mc_group_id = 1

        # TODO/FIXME - Need to add logic to parse the topology to determine
        #     egress ports being used on the switch.

        if sw_info['name'] == 'gateway1':
            replicas = [{'egress_port': '1', 'instance': '1'},
                        {'egress_port': '2', 'instance': '1'},
                        {'egress_port': '3', 'instance': '1'},
                        {'egress_port': '4', 'instance': '1'}]
        else:
            replicas = [{'egress_port': '1', 'instance': '1'},
                        {'egress_port': '2', 'instance': '1'},
                        {'egress_port': '3', 'instance': '1'}]
        multicast_entry = self.p4info_helper.build_multicast_group_entry(mc_group_id, replicas)
        logger.info('Build Multicast Entry: %s', multicast_entry)
        sw.write_multicast_entry(multicast_entry)
        table_entry = self.p4info_helper.build_table_entry(
            table_name='{}.arp_flood_t'.format(self.p4_ingress),
            match_fields={'hdr.ethernet.dst_mac': 'ff:ff:ff:ff:ff:ff'},
            action_name='{}.arp_flood'.format(self.p4_ingress),
            action_params={
                'ip_srcAddr': sw_info['public_ip'],
                'srcAddr': sw_info['mac']
            })
        sw.write_table_entry(table_entry)

    def add_data_forward(self, sw, sw_info, src_ip, mac, port):
        logger.info("%s - Check if %s belongs to: %s", sw_info['name'], src_ip, self.known_devices)
        if src_ip not in self.known_devices:
            logger.info("Adding unique table entry on %s for %s", sw_info['name'], src_ip)
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

    def add_nat_table(self, sw, sw_info, udp_source_port, tcp_source_port, source_ip):
        gateway_public_ip = sw_info['public_ip']
        logger.info("Adding nat table entries on %s for %s", sw_info['name'], source_ip)
        logger.info("Check if %s not in %s for %s", udp_source_port, self.nat_udp_ports, sw_info['name'])
        # NAT Table Entries to handle UDP packets
        if udp_source_port and udp_source_port not in self.nat_udp_ports:
            table_entry = self.p4info_helper.build_table_entry(
                table_name='{}.udp_local_to_global_t'.format(self.p4_ingress),
                match_fields={
                    'hdr.udp.src_port': udp_source_port,
                    'hdr.ipv4.srcAddr': (source_ip, 32)
                },
                action_name='{}.udp_local_to_global'.format(self.p4_ingress),
                action_params={
                    'src_port': int("50"+str(sw_info['id'])+str(self.udp_port_count)),
                    'ip_srcAddr': gateway_public_ip
                })
            sw.write_table_entry(table_entry)
            table_entry = self.p4info_helper.build_table_entry(
                table_name='{}.udp_global_to_local_t'.format(self.p4_ingress),
                match_fields={
                    'hdr.udp.dst_port': int("50"+str(sw_info['id'])+str(self.udp_port_count)),
                    'hdr.ipv4.dstAddr': (gateway_public_ip, 32)
                },
                action_name='{}.udp_global_to_local'.format(self.p4_ingress),
                action_params={
                    'dst_port': udp_source_port,
                    'ip_dstAddr': source_ip
                })
            sw.write_table_entry(table_entry)
            self.udp_port_count = self.udp_port_count + 1
            self.nat_udp_ports.add(udp_source_port)
            logger.info("UDP NAT table entry added on %s", sw_info['name'])
        elif tcp_source_port and tcp_source_port not in self.nat_tcp_ports:
            # NAT Table Entries to handle TCP packets
            table_entry = self.p4info_helper.build_table_entry(
                table_name='{}.tcp_local_to_global_t'.format(self.p4_ingress),
                match_fields={
                    'hdr.tcp.src_port': tcp_source_port,
                    'hdr.ipv4.srcAddr': (source_ip, 32)
                },
                action_name='{}.tcp_local_to_global'.format(self.p4_ingress),
                action_params={
                    'src_port': int("50"+str(sw_info['id'])+str(self.tcp_port_count)),
                    'ip_srcAddr': gateway_public_ip
                })
            sw.write_table_entry(table_entry)
            table_entry = self.p4info_helper.build_table_entry(
                table_name='{}.tcp_global_to_local_t'.format(self.p4_ingress),
                match_fields={
                    'hdr.tcp.dst_port': int("50"+str(sw_info['id'])+str(self.tcp_port_count)),
                    'hdr.ipv4.dstAddr': (gateway_public_ip, 32)
                },
                action_name='{}.tcp_global_to_local'.format(self.p4_ingress),
                action_params={
                    'dst_port': tcp_source_port,
                    'ip_dstAddr': source_ip
                })
            sw.write_table_entry(table_entry)
            self.tcp_port_count = self.tcp_port_count + 1
            self.nat_tcp_ports.add(tcp_source_port)
            logger.info("TCP NAT table entry added on %s", sw_info['name'])

    def interpret_nat_digest(self, sw, sw_info, digest_data):
        logger.debug("Digest data %s", digest_data)
        for members in digest_data:
            logger.debug("Members: %s", members)
            if members.WhichOneof('data') == 'struct':
                udp_source_port = decode_num(members.struct.members[0].bitstring)
                logger.info('Learned UDP Source Port from %s is: %s', sw_info['name'], udp_source_port)
                tcp_source_port = decode_num(members.struct.members[1].bitstring)
                logger.info('Learned TCP Source Port from %s is: %s', sw_info['name'], tcp_source_port)
                source_ip = decode_ipv4(members.struct.members[2].bitstring)
                logger.info('Learned Source IP Address from %s is: %s', sw_info['name'], source_ip)
                self.add_nat_table(sw, sw_info, udp_source_port, tcp_source_port, source_ip)
