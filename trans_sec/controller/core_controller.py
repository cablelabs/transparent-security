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

from trans_sec.bfruntime_lib.core_switch import (CoreSwitch as BFRTSwitch)


logger = getLogger('core_controller')


class CoreController(AbstractController):
    """
    Implementation of the controller for a switch running the core.p4 program
    """

    def __init__(self, platform, p4_build_out, topo, log_dir, load_p4=True):
        super(self.__class__, self).__init__(
            platform, p4_build_out, topo, CORE_CTRL_KEY, log_dir, load_p4)

    def instantiate_switch(self, sw_info):
        logger.info('Instantiating switch with arch - [%s]', sw_info)
        logger.info('Instantiating BFRT CoreSwitch')
        return BFRTSwitch(sw_info=sw_info)

    def __get_core_switch(self):
        return self.switches[0]

    def setup_telem_rpt(self, **kwargs):
        for switch in self.switches:
            if switch.mac == kwargs['switch_mac']:
                switch.setup_telemetry_rpt(
                    kwargs['switch_ip'], kwargs['ae_ip'], kwargs['ae_mac'],
                    kwargs['port'])

    def set_trpt_sampling_value(self, sample_size):
        for switch in self.switches:
            switch.set_trpt_sampling_value(sample_size)

    def remove_telem_rpt(self, **kwargs):
        for switch in self.switches:
            if switch.mac == kwargs['switch_mac']:
                switch.remove_telemetry_rpt(kwargs['ae_ip'], kwargs['port'])

    def add_attacker(self, attack, host):
        pass

    def remove_attacker(self, attack, host):
        pass
