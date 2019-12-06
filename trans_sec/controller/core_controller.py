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
from trans_sec.utils import convert

logger = getLogger('core_controller')


class CoreController(AbstractController):
    """
    Implementation of the controller for a switch running the core.p4 program
    """
    def __init__(self, p4_build_out, topo, log_dir):
        """
        Constructor
        :param p4_build_out:
        :param topo:
        :param log_dir:
        """
        super(self.__class__, self).__init__(
            p4_build_out, topo, 'core', ['MyIngress.forwardedPackets'],
            log_dir)

    def make_rules(self, sw, sw_info, north_facing_links,
                   south_facing_links):
        """
        Overrides the abstract method from super
        :param sw: switch object
        :param sw_info: switch info object
        :param north_facing_links: northbound links
        :param south_facing_links: southbound links
        """

        for south_facing_link in south_facing_links:
            south_device = self.topo.get('hosts').get(south_facing_link.get(
                'south_node'))
            if not south_device:
                south_device = self.topo.get('switches').get(
                    south_facing_link.get('south_node'))
                if south_device is None:
                    raise Exception('Could not locate south node device')

            logger.info('Core: %s connects to south device %s on port %s',
                        sw_info['name'], south_device['name'],
                        str(south_facing_link.get('south_facing_port')))

        for north_facing_link in north_facing_links:
            north_device = self.topo.get('hosts').get(north_facing_link.get(
                'north_node'))
            if north_device:
                logger.info(
                    'Core: %s connects to Internet: %s on physical port %s to'
                    ' ip %s:%s',
                    sw_info['name'], north_device['name'],
                    str(north_facing_link.get('north_facing_port')),
                    north_device.get('ip'), str(north_device.get('ip_port')))
                table_entry = self.p4info_helper.build_table_entry(
                    table_name='MyIngress.data_forward_t',
                    match_fields={
                        'hdr.ipv4.dstAddr': (north_device.get('ip'), 32)
                    },
                    action_name='MyIngress.data_forward',
                    action_params={
                        'dstAddr': north_device.get('mac'),
                        'port': north_facing_link.get('north_facing_port')
                    })
                sw.write_table_entry(table_entry)
                logger.info(
                    'Installed Host %s ipv4 cloning rule on %s',
                    north_device.get('ip'), sw.name)

        clone_entry = self.p4info_helper.build_clone_entry(sw_info['clone_egress'])
        sw.write_clone_entries(clone_entry)
        logger.info('Installed clone on %s' % sw.name)
