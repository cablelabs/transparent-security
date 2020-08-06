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
from trans_sec.controller.ddos_sdn_controller import CORE_CTRL_KEY

logger = getLogger('core_controller')

try:
    from trans_sec.p4runtime_lib.core_switch import CoreSwitch as P4RTSwitch
except Exception as e:
    logger.warning(
        "Error [%s] - while attempting to import "
        "trans_sec.p4runtime_lib.core_switch.CoreSwitch", e)

try:
    from trans_sec.bfruntime_lib.core_switch import (
        CoreSwitch as BFRTSwitch)
except Exception as e:
    logger.warning('Could not import bfrt classes')


class CoreController(AbstractController):

    def __init__(self, platform, p4_build_out, topo, log_dir, load_p4=True):
        super(self.__class__, self).__init__(
            platform, p4_build_out, topo, CORE_CTRL_KEY, log_dir, load_p4)

    """
    Implementation of the controller for a switch running the core.p4 program
    """
    def instantiate_switch(self, sw_info):
        if 'arch' in sw_info and sw_info['arch'] == 'tna':
            return BFRTSwitch(
                sw_info=sw_info,
                proto_dump_file='{}/{}-switch-controller.log'.format(
                    self.log_dir, sw_info['name']))
        else:
            return P4RTSwitch(
                sw_info=sw_info,
                proto_dump_file='{}/{}-switch-controller.log'.format(
                    self.log_dir, sw_info['name']))

    def make_rules(self, sw, north_facing_links, south_facing_links,
                   add_di):
        super(self.__class__, self).make_rules(
            sw, north_facing_links, south_facing_links, False)

        logger.info('Activating clone on device [%s] to port [%s]',
                    sw.grpc_addr, sw.sw_info['clone_egress'])
        sw.write_clone_entries(sw.sw_info['clone_egress'])
        logger.info('Installed clone on %s' % sw.name)

        ae_ip = None
        trpt_dict = sw.sw_info.get('telemetry_rpt')
        if trpt_dict:
            logger.info('Activating Telem Rpt on device [%s]', sw.grpc_addr)
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
            self.__make_int_rules(sw)
        else:
            logger.info('Not inserting anything to data_inspection_t')

        logger.info('Completed rules for device [%s]', sw.sw_info['mac'])

    @staticmethod
    def __make_int_rules(sw):
        logger.info('Adding table entry on core for data_inspection_t')
        sw.add_data_inspection(sw.sw_info['id'], None)

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
