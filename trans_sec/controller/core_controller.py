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
    logger.debug('Importing CoreSwitch as P4RTSwitch')
    from trans_sec.p4runtime_lib.core_switch import CoreSwitch as P4RTSwitch
    logger.debug('Imported CoreSwitch as P4RTSwitch')
except Exception as e:
    logger.warning(
        "Error [%s] - while attempting to import "
        "trans_sec.p4runtime_lib.core_switch.CoreSwitch", e)

try:
    logger.debug('Importing CoreSwitch as BFRTSwitch')
    from trans_sec.bfruntime_lib.core_switch import (
        CoreSwitch as BFRTSwitch)
    logger.debug('Imported CoreSwitch as BFRTSwitch')
except Exception as e:
    logger.warning('Could not import bfrt classes')


class CoreController(AbstractController):
    """
    Implementation of the controller for a switch running the core.p4 program
    """

    def __init__(self, platform, p4_build_out, topo, log_dir, load_p4=True):
        super(self.__class__, self).__init__(
            platform, p4_build_out, topo, CORE_CTRL_KEY, log_dir, load_p4)

    def instantiate_switch(self, sw_info):
        logger.info('Instantiating switch with arch - [%s]', sw_info)
        if 'arch' in sw_info and sw_info['arch'] == 'tna':
            logger.info('Instantiating BFRT CoreSwitch')
            return BFRTSwitch(sw_info=sw_info)
        else:
            return P4RTSwitch(
                sw_info=sw_info,
                proto_dump_file='{}/{}-switch-controller.log'.format(
                    self.log_dir, sw_info['name']))

    def __get_core_switch(self):
        return self.switches[0]

    def get_ae_ip(self):
        core_switch = self.__get_core_switch()
        if core_switch:
            return core_switch.read_ae_ip()

    def setup_telem_rpt(self, **kwargs):
        for switch in self.switches:
            if switch.mac == kwargs['switch_mac']:
                switch.setup_telemetry_rpt(kwargs['ae_ip'], kwargs['port'])

    def remove_telem_rpt(self, **kwargs):
        for switch in self.switches:
            if switch.mac == kwargs['switch_mac']:
                switch.remove_telemetry_rpt(kwargs['ae_ip'], kwargs['port'])

    def add_attacker(self, attack, host):
        pass

    def remove_attacker(self, attack, host):
        pass
