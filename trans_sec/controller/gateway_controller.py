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

logger = getLogger('gateway_controller')


class GatewayController(AbstractController):
    """
    Implementation of the controller for a switch running the aggregate.p4
    program
    """
    def __init__(self, platform, p4_build_out, topo, log_dir, load_p4=True):
        super(self.__class__, self).__init__(
            platform, p4_build_out, topo, 'gateway',
            ['MyIngress.forwardedPackets', 'MyIngress.droppedPackets'],
            log_dir, load_p4)

    def make_rules(self, sw, sw_info, north_facing_links, south_facing_links):
        """
        Overrides the abstract method from super
        :param sw: switch object
        :param sw_info: switch info object
        :param north_facing_links: northbound links
        :param south_facing_links: southbound links
        """
        if 0 < len(north_facing_links) < 2:
            aggregate_link = north_facing_links[0]
            aggregate = self.topo['switches'][aggregate_link['north_node']]
            logger.info('Gateway: ' + sw_info['name'] +
                        ' connects northbound to Aggregate: ' +
                        aggregate.get('name') +
                        ' on physical port ' +
                        str(aggregate_link.get('north_facing_port')) +
                        ' to physical port ' +
                        str(aggregate_link.get('south_facing_port')))

            for device_link in south_facing_links:
                device = self.topo['hosts'].get(device_link['south_node'])
                logger.info('Gateway: ' + sw_info['name'] +
                            ' connects to Device: ' + device['name'] +
                            ' on physical port ' +
                            str(device_link.get('south_facing_port')) +
                            ' to IP ' + device.get('ip') +
                            ':' + str(device.get('ip_port')))

                # Northbound Traffic Inspection
                table_entry = self.p4info_helper.build_table_entry(
                    table_name='MyIngress.data_inspection_t',
                    match_fields={
                        'hdr.ethernet.srcAddr': device['mac']
                    },
                    action_name='MyIngress.data_inspect_packet',
                    action_params={
                        'device': device['id']
                    })
                sw.write_table_entry(table_entry)
                logger.info('Installed Northbound Packet Inspection '
                            'from %s', device.get('ip'))

            # Northbound Routing
            table_entry = self.p4info_helper.build_table_entry(
                table_name='MyIngress.data_forward_t',
                match_fields={
                    'standard_metadata.ingress_port': 1
                },
                action_name='MyIngress.data_forward',
                action_params={
                    'dstAddr': aggregate['mac'],
                    'port': aggregate_link['north_facing_port'],
                    'l2ptr': 0
                })
            sw.write_table_entry(table_entry)
            logger.info('Installed Northbound from port 1 to port %d',
                        aggregate_link.get('north_facing_port'))
            # Northbound Routing
            table_entry = self.p4info_helper.build_table_entry(
                table_name='MyIngress.data_forward_t',
                match_fields={
                    'standard_metadata.ingress_port': 2
                },
                action_name='MyIngress.data_forward',
                action_params={
                    'dstAddr': aggregate['mac'],
                    'port': aggregate_link['north_facing_port'],
                    'l2ptr': 0
                })
            sw.write_table_entry(table_entry)
            logger.info('Installed Northbound from port 2 to port %d',
                        aggregate_link.get('north_facing_port'))
            # Northbound Routing
            table_entry = self.p4info_helper.build_table_entry(
                table_name='MyIngress.data_forward_t',
                match_fields={
                    'standard_metadata.ingress_port': 3
                },
                action_name='MyIngress.data_forward',
                action_params={
                    'dstAddr': aggregate['mac'],
                    'port': aggregate_link['north_facing_port'],
                    'l2ptr': 0
                })
            sw.write_table_entry(table_entry)
            logger.info('Installed Northbound from port 3 to port %d',
                        aggregate_link.get('north_facing_port'))
        else:
            logger.error('Wrong number of nb switches on gateway')
            logger.error(sw_info.get('name'))
