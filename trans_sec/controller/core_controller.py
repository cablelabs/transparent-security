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
from trans_sec.controller.ddos_sdn_controller import GATEWAY_CTRL_KEY, \
    CORE_CTRL_KEY
from trans_sec.p4runtime_lib.bmv2 import CoreSwitch

logger = getLogger('core_controller')


class CoreController(AbstractController):

    def __init__(self, platform, p4_build_out, topo, log_dir, load_p4=True):
        super(self.__class__, self).__init__(
            platform, p4_build_out, topo, CORE_CTRL_KEY, log_dir, load_p4)

    """
    Implementation of the controller for a switch running the core.p4 program
    """
    def instantiate_switch(self, sw_info):
        return CoreSwitch(
            p4info_helper=self.p4info_helper,
            sw_info=sw_info,
            proto_dump_file='{}/{}-switch-controller.log'.format(
                self.log_dir, sw_info['name']))

    def make_rules(self, sw, north_facing_links, south_facing_links,
                   add_di):
        super(self.__class__, self).make_rules(
            sw, north_facing_links, south_facing_links, add_di)

        clone_entry = self.p4info_helper.build_clone_entry(
            sw.sw_info['clone_egress'])
        sw.write_clone_entries(clone_entry)
        logger.info('Installed clone on %s' % sw.name)

        ae_ip = None
        trpt_dict = sw.sw_info.get('telemetry_rpt')
        if trpt_dict:
            if trpt_dict['type'] == 'host':
                host_dict = self.topo['hosts'].get(trpt_dict['name'])
                if host_dict:
                    ae_ip = host_dict.get('ip')
            elif trpt_dict['type'] == 'external':
                ext_dict = self.topo['external'].get(trpt_dict['name'])
                if ext_dict:
                    ae_ip = ext_dict.get('ip')

            if ae_ip:
                logger.info('Telemetry report to be sent to - [%s]', ae_ip)
                sw.setup_telemetry_rpt(ae_ip)
            else:
                logger.warning('Telemetry report not to be activated '
                               'Could not obtain IP to ae')
        else:
            logger.warning('Telemetry report not configured')

        if add_di:
            for north_link in north_facing_links:
                if 'l2ptr' in north_link:
                    self.__make_int_rules(sw)

        logger.info('Completed rules for device [%s]', sw.sw_info['mac'])

    def __make_int_rules(self, sw):
        for name, switch in self.topo['switches'].items():
            if switch.get('type') == GATEWAY_CTRL_KEY:
                logger.info(
                    'Adding data inspection for packets from device [%s]',
                    sw.sw_info['mac'])
                sw.add_data_inspection(sw.sw_info['id'], switch['mac'])

    def make_north_rules(self, sw, north_link):
        north_device = self.topo['hosts'].get(north_link['north_node'])
        if north_device:
            logger.info(
                'Core: %s connects to Internet: %s on physical port %s to'
                ' ip %s:%s',
                sw.name, north_device['name'],
                north_link.get('north_facing_port'),
                north_device.get('ip'), str(north_device.get('ip_port')))
            logger.info(
                'Adding data_forward entry to forward packets to  port - [%s]',
                north_link['north_facing_port'])

            logger.info(
                'Installed Host %s ipv4 cloning rule on %s',
                north_device.get('ip'), sw.name)
