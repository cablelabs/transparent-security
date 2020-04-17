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
import socket
from logging import getLogger

from trans_sec.controller.abstract_controller import AbstractController

logger = getLogger('core_controller')


class CoreController(AbstractController):
    """
    Implementation of the controller for a switch running the core.p4 program
    """
    def __init__(self, platform, p4_build_out, topo, log_dir, load_p4=True):
        """
        Constructor
        :param platform: the P4 platforms on which the controllers are running
        :param p4_build_out: p4 artifacts directory
        :param topo: the topology config dict object
        :param log_dir: the directory to send the logs
        """
        super(self.__class__, self).__init__(
            platform, p4_build_out, topo, 'core', list(), log_dir, load_p4,
            'TpsCoreIngress')
        self.p4_egress = 'TpsCoreEgress'
        self.known_devices = set()

    def make_rules(self, sw, sw_info, north_facing_links, south_facing_links):
        super(self.__class__, self).make_rules(
            sw, sw_info, north_facing_links, south_facing_links)
        clone_entry = self.p4info_helper.build_clone_entry(
            sw_info['clone_egress'])
        sw.write_clone_entries(clone_entry)
        logger.info('Installed clone on %s' % sw.name)

        # TODO - Make this more configurable and support at least 2 ports as
        #  well as IPv6 create an optional configuration item in the topology
        #  specifically for the ae_ip
        ae_ip = self.topo['external']['analytics_engine']['ip']
        ae_ip = socket.gethostbyname(ae_ip)
        logger.info('Starting telemetry report for INT headers with dst_port '
                    'value of 555 to AE IP [%s]', ae_ip)
        table_name = '{}.setup_telemetry_rpt_t'.format(self.p4_egress)
        action_name = '{}.setup_telem_rpt_ipv4'.format(self.p4_egress)
        match_fields = {
            'hdr.udp_int.dst_port': 555
        }
        action_params = {
            'ae_ip': ae_ip
        }
        table_entry = self.p4info_helper.build_table_entry(
            table_name=table_name,
            match_fields=match_fields,
            action_name=action_name,
            action_params=action_params)
        sw.write_table_entry(table_entry)

        logger.info('self.topo - [%s]', self.topo)
        logger.info('north_facing_links - [%s]', north_facing_links)
        logger.info('south_facing_links - [%s]', south_facing_links)
        logger.info('sw_info - [%s]', sw_info)

        for north_link in north_facing_links:
            if 'l2ptr' in north_link:
                self.__make_int_rules(sw, sw_info, north_link,
                                      south_facing_links)

    def __make_int_rules(self, sw, sw_info, north_link, south_facing_links):
        for south_link in south_facing_links:
            south_node_name = south_link['south_node']
            south_node_mac = self.topo['switches'][south_node_name]['mac']
            action_params = {
                'switch_id': sw_info['id'],
            }
            table_name = '{}.data_inspection_t'.format(self.p4_ingress)
            action_name = '{}.data_inspect_packet'.format(self.p4_ingress)
            match_fields = {'hdr.ethernet.src_mac': south_node_mac}
            logger.info(
                'Insert params into table - [%s] for action [%s] ',
                'with params [%s] fields [%s] key hdr.ethernet.src_mac [%s]',
                table_name, action_name, action_params, match_fields,
                south_node_mac)
            table_entry = self.p4info_helper.build_table_entry(
                table_name=table_name,
                match_fields=match_fields,
                action_name=action_name,
                action_params=action_params)
            sw.write_table_entry(table_entry)

    def make_north_rules(self, sw, sw_info, north_link):
        north_device = self.topo['hosts'].get(north_link['north_node'])
        if north_device:
            logger.info(
                'Core: %s connects to Internet: %s on physical port %s to'
                ' ip %s:%s',
                sw_info['name'], north_device['name'],
                north_link.get('north_facing_port'),
                north_device.get('ip'), str(north_device.get('ip_port')))
            logger.info(
                'Adding data_forward entry to forward packets to  port - [%s]',
                north_link['north_facing_port'])

            # Add entry for forwarding IPv6 packets
            table_entry = self.p4info_helper.build_table_entry(
                table_name='{}.data_forward_ipv6_t'.format(self.p4_ingress),
                match_fields={
                    'hdr.ipv6.dstAddr': (north_device['ipv6'], 128),
                },
                action_name='{}.data_forward'.format(self.p4_ingress),
                action_params={
                    'dstAddr': north_device['mac'],
                    'port': north_link['north_facing_port']
                })
            sw.write_table_entry(table_entry)

            logger.info(
                'Installed Host %s ipv4 cloning rule on %s',
                north_device.get('ip'), sw.name)

    def set_multicast_group(self, sw, sw_info):
        mc_group_id = 1

        # TODO/FIXME - Need to add logic to parse the topology to determine
        #     egress ports being used on the switch.

        replicas = [
            {'egress_port': '1', 'instance': '1'},
            {'egress_port': '2', 'instance': '1'}]

        multicast_entry = self.p4info_helper.build_multicast_group_entry(mc_group_id,replicas)
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
