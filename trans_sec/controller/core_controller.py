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

    def make_rules(self, sw, sw_info, north_facing_links, south_facing_links):
        super(self.__class__, self).make_rules(
            sw, sw_info, north_facing_links, south_facing_links)
        clone_entry = self.p4info_helper.build_clone_entry(
            sw_info['clone_egress'])
        sw.write_clone_entries(clone_entry)
        logger.info('Installed clone on %s' % sw.name)

    def make_north_rules(self, sw, sw_info, north_link):
        north_device = self.topo['hosts'].get(north_link['north_node'])
        if north_device:
            logger.info(
                'Core: %s connects to Internet: %s on physical port %s to'
                ' ip %s:%s',
                sw_info['name'], north_device['name'],
                north_link.get('north_facing_port'),
                north_device.get('ip'), str(north_device.get('ip_port')))
            table_entry = self.p4info_helper.build_table_entry(
                table_name='{}.data_forward_t'.format(self.p4_ingress),
                match_fields={
                    'hdr.ipv4.dstAddr': (north_device['ip'], 32)
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

    def make_south_rules(self, sw, sw_info, south_link):
        south_device = self.topo['hosts'].get(south_link['south_node'])
        if not south_device:
            south_device = self.topo['switches'].get(south_link['south_node'])
            if south_device is None:
                raise Exception('Could not locate south node device')

        logger.info('Core: %s connects to south device %s on port %s',
                    sw_info['name'], south_device['name'],
                    str(south_link.get('south_facing_port')))
