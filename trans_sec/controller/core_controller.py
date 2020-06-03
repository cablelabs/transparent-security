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

    def make_rules(self, sw, sw_info, north_facing_links, south_facing_links,
                   add_di):
        super(self.__class__, self).make_rules(
            sw, sw_info, north_facing_links, south_facing_links, add_di)
        clone_entry = self.p4info_helper.build_clone_entry(
            sw_info['clone_egress'])
        sw.write_clone_entries(clone_entry)
        logger.info('Installed clone on %s' % sw.name)

        ae_ip = None
        trpt_dict = sw_info['telemetry_rpt']
        if trpt_dict['type'] == 'host':
            ae_ip = self.topo['hosts'][trpt_dict['name']]['ip']
        elif trpt_dict['type'] == 'external':
            ae_ip = self.topo['external'][trpt_dict['name']]['ip']

        if ae_ip:
            ae_ip_addr = socket.gethostbyname(ae_ip)
            logger.info(
                'Starting telemetry report for INT headers with dst_port '
                'value of 555 to AE IP [%s]', ae_ip_addr)
            table_name = '{}.setup_telemetry_rpt_t'.format(self.p4_egress)
            action_name = '{}.setup_telem_rpt_ipv4'.format(self.p4_egress)
            match_fields = {
                'hdr.udp_int.dst_port': 555
            }
            action_params = {
                'ae_ip': ae_ip_addr
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

        if add_di:
            for north_link in north_facing_links:
                if 'l2ptr' in north_link:
                    self.__make_int_rules(sw, sw_info, north_link,
                                          south_facing_links)

    def __make_int_rules(self, sw, sw_info, north_link, south_facing_links):
        for name, switch in self.topo['switches'].items():
            if switch.get('type') == 'gateway':
                action_params = {
                    'switch_id': sw_info['id'],
                }
                table_name = '{}.data_inspection_t'.format(self.p4_ingress)
                action_name = '{}.data_inspect_packet'.format(self.p4_ingress)
                match_fields = {'hdr.ethernet.src_mac': switch.get('mac')}
                logger.info(
                    'Insert params into table - [%s] for action [%s] ',
                    'with params [%s] fields [%s] key hdr.ethernet.src_mac [%s]',
                    table_name, action_name, action_params, match_fields,
                    switch.get('mac'))
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

            logger.info(
                'Installed Host %s ipv4 cloning rule on %s',
                north_device.get('ip'), sw.name)

    def add_data_forward(self, sw, sw_info, mac, port):
        logger.info("%s - Check if %s belongs to: %s", sw_info['name'], mac, self.known_devices)
        if sw_info['name'] not in self.known_devices:
            self.known_devices[sw_info['name']] = []
        if mac not in self.known_devices[sw_info['name']]:
            logger.info("Adding unique table entry on %s for %s", sw_info['name'], mac)
            table_entry = self.p4info_helper.build_table_entry(
                table_name='{}.data_forward_t'.format(self.p4_ingress),
                match_fields={
                    'hdr.ethernet.dst_mac': mac
                },
                action_name='{}.data_forward'.format(self.p4_ingress),
                action_params={'port': port}
                )
            sw.write_table_entry(table_entry)
            table_entry = self.p4info_helper.build_table_entry(
                table_name='{}.arp_forward_t'.format(self.p4_ingress),
                match_fields={
                    'hdr.ethernet.dst_mac': mac
                },
                action_name='{}.arp_forward'.format(self.p4_ingress),
                action_params={'port': port}
            )
            sw.write_table_entry(table_entry)
            self.known_devices[sw_info['name']].append(mac)
