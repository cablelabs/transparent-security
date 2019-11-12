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
    def __init__(self, p4_build_out, topo, log_dir):
        super(self.__class__, self).__init__(
            p4_build_out, topo, 'aggregate',
            ['MyIngress.forwardedPackets', 'MyIngress.droppedPackets'],
            log_dir)

    def make_rules(self, sw, sw_info, north_facing_links, south_facing_links):
        """
        Overrides the abstract method from super
        :param sw: switch object
        :param sw_info: switch info object
        :param north_facing_links: northbound links
        :param south_facing_links: southbound links
        """
        for north_facing_link in north_facing_links:
            core = self.topo.get('switches').get(
                north_facing_link.get('north_node'))
            logger.info(
                'Aggregate: %s connects northbound to Core: %s on physical '
                'port %s to physical port %s',
                sw_info['name'], core['name'],
                str(north_facing_link.get('north_facing_port')),
                str(north_facing_link.get('south_facing_port')))

            inet = self.topo.get('hosts').get('inet')

            table_entry = self.p4info_helper.build_table_entry(
                table_name='MyIngress.data_forward_t',
                match_fields={
                    'hdr.ipv4.dstAddr': (inet.get('ip'), 32)
                },
                action_name='MyIngress.data_forward',
                action_params={
                    'dstAddr': core.get('mac'),
                    'port': north_facing_link.get('north_facing_port'),
                    'l2ptr': 0
                })
            sw.write_table_entry(table_entry)
            logger.info('Installed Northbound from port %s to port %s',
                        north_facing_link.get('north_facing_port'),
                        north_facing_link.get('south_facing_port'))

        for south_link in south_facing_links:
            if self.topo.get('switches').get(
                    south_link.get('south_node')) is not None:
                device = self.topo.get('switches').get(
                    south_link.get('south_node'))
                logger.info(
                    'Aggregate: %s connects to Gateway: %s on physical '
                    'port %s to physical port %s',
                    sw_info['name'], device['name'],
                    str(south_link.get('south_facing_port')),
                    str(south_link.get('north_facing_port')))

            elif self.topo.get('hosts').get(
                    south_link.get('south_node')) is not None:
                device = self.topo.get('hosts').get(
                    south_link.get('south_node'))
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
                table_entry = self.p4info_helper.build_table_entry(
                    table_name='MyIngress.data_inspection_t',
                    match_fields={
                        'hdr.ethernet.srcAddr': device.get('mac')
                    },
                    action_name='MyIngress.data_inspect_packet',
                    action_params={
                        'device': device.get('id')
                    })
                sw.write_table_entry(table_entry)
                logger.info(
                    'Installed Northbound Packet Inspection from %s',
                    device.get('mac'))
