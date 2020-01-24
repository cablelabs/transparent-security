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
            ['TpsAggIngress.forwardedPackets', 'TpsAggIngress.droppedPackets'],
            log_dir, load_p4, 'TpsAggIngress')

    def make_north_rules(self, sw, sw_info, north_link):
        if north_link.get('north_facing_port'):
            logger.info('Creating north switch rules - [%s]', north_link)
            north_node = self.topo['switches'][north_link['north_node']]
            logger.info(
                'Aggregate: %s connects northbound to Core: %s on physical '
                'port %s to physical port %s',
                sw_info['name'], north_node,
                north_link.get('north_facing_port'),
                north_link.get('south_facing_port'))

            inet = self.topo['hosts']['inet']

            table_entry = self.p4info_helper.build_table_entry(
                table_name='{}.data_forward_t'.format(self.p4_ingress),
                match_fields={
                    'hdr.ipv4.dstAddr': (inet['ip'], 32)
                },
                action_name='{}.data_forward'.format(self.p4_ingress),
                action_params={
                    'dstAddr': north_node['mac'],
                    'port': north_link['north_facing_port'],
                    'l2ptr': 0
                })
            sw.write_table_entry(table_entry)
            logger.info('Installed Northbound from port %s to port %s',
                        north_link.get('north_facing_port'),
                        north_link.get('south_facing_port'))
        else:
            logger.info('No north links to install')

    def make_south_rules(self, sw, sw_info, south_link):
        if south_link.get('south_facing_port'):
            logger.info('Creating south switch rules - [%s]', south_link)
            if self.topo['switches'].get(south_link['south_node']):
                device = self.topo['switches'][south_link['south_node']]
                logger.info(
                    'Aggregate: %s connects to Gateway: %s on physical '
                    'port %s to physical port %s',
                    sw_info['name'], device['name'],
                    str(south_link.get('south_facing_port')),
                    str(south_link.get('north_facing_port')))
            elif self.topo['hosts'].get(south_link['south_node']) is not None:
                device = self.topo['hosts'][south_link['south_node']]
                logger.info(
                    'Aggregate: %s connects to Device: %s on physical '
                    'port %s',
                    sw_info['name'], device['name'],
                    str(south_link.get('south_facing_port')))
            else:
                raise StandardError(
                    'South Bound Link for %s, %s does not exist in topology' %
                    (sw.name, south_link.get('south_node')))

            if device is not None:
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
                    'Installed Northbound Packet Inspection for device with'
                    ' MAC - [%s] with action params - [%s]',
                    device.get('mac'), action_params)
        else:
            logger.info('No south links to install')
