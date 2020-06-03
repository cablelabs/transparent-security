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
from trans_sec.controller.abstract_controller import AbstractController

logger = getLogger('aggregate_controller')


class AggregateController(AbstractController):
    """
    Implementation of the controller for a switch running the aggregate.p4
    program
    """
    def __init__(self, platform, p4_build_out, topo, log_dir, load_p4=True):
        super(self.__class__, self).__init__(
            platform, p4_build_out, topo, 'aggregate',
            ['TpsAggIngress.forwardedPackets'],
            log_dir, load_p4, 'TpsAggIngress')

    def make_north_rules(self, sw, sw_info, north_link):
        if north_link.get('north_facing_port'):
            logger.info('Creating north switch rules - [%s]', north_link)

            # north_node = self.topo['switches'][north_link['north_node']]
            if (self.topo.get('switches')
                    and north_link['north_node'] in self.topo['switches']):
                logger.debug('North node from switches')
                north_node = self.topo['switches'][north_link['north_node']]
            else:
                logger.debug('North node from hosts')
                north_node = self.topo['hosts'][north_link['north_node']]

            logger.info(
                'Aggregate: %s connects northbound to Core: %s on physical '
                'port %s to physical port %s',
                sw_info['name'], north_node,
                north_link.get('north_facing_port'),
                north_link.get('south_facing_port'))

            logger.info('Installed Northbound from port %s to port %s',
                        north_link.get('north_facing_port'),
                        north_link.get('south_facing_port'))
        else:
            logger.info('No north links to install')

    def add_data_inspection(self, sw, device, sw_info):
        action_params = {
            'device': device['id'],
            'switch_id': sw_info['id']
        }
        table_entry = self.p4info_helper.build_table_entry(
            table_name='{}.data_inspection_t'.format(self.p4_ingress),
            match_fields={'hdr.ethernet.src_mac': device['mac']},
            action_name='{}.data_inspect_packet'.format(
                self.p4_ingress),
            action_params=action_params)
        sw.write_table_entry(table_entry)
        logger.info(
            'Installed Northbound Packet Inspection for device - [%s]'
            ' with MAC - [%s] with action params - [%s]',
            self.switch_type, device.get('mac'), action_params)

    def add_data_forward(self, sw, sw_info, mac, port):
        logger.info("Aggregate - Check if %s belongs to: %s", mac, self.known_devices)
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
            self.known_devices[sw_info['name']].append(mac)
