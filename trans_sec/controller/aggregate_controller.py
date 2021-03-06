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
from trans_sec.controller.ddos_sdn_controller import AGG_CTRL_KEY

logger = getLogger('aggregate_controller')

try:
    from trans_sec.p4runtime_lib.aggregate_switch import (
        AggregateSwitch as P4RTSwitch)
except Exception as e:
    logger.warning(
        "Error [%s] - while attempting to import "
        "trans_sec.p4runtime_lib.aggregate_switch.AggregateSwitch", e)

try:
    from trans_sec.bfruntime_lib.aggregate_switch import (
        AggregateSwitch as BFRTSwitch)
except Exception as e:
    logger.warning(
        "Error [%s] - while attempting to import "
        "trans_sec.bfruntime_lib.aggregate_switch.AggregateSwitch", e)


class AggregateController(AbstractController):
    """
    Implementation of the controller for a switch running the aggregate.p4
    program
    """
    def __init__(self, platform, p4_build_out, topo, log_dir, load_p4=True):
        super(self.__class__, self).__init__(
            platform, p4_build_out, topo, AGG_CTRL_KEY, log_dir, load_p4)

    def instantiate_switch(self, sw_info):
        if 'arch' in sw_info and sw_info['arch'] == 'tna':
            logger.info('Instantiating BFRT AggregateSwitch')
            return BFRTSwitch(sw_info=sw_info)
        else:
            return P4RTSwitch(
                sw_info=sw_info,
                proto_dump_file='{}/{}-switch-controller.log'.format(
                    self.log_dir, sw_info['name']))

    def __get_agg_switch(self):
        return self.switches[0]

    def add_attacker(self, attack, host):
        logger.info('Attack received by the controller of type [%s] - [%s]',
                    self.switch_type, attack)
        agg_switch = self.__get_agg_switch()
        if agg_switch:
            logger.info("Adding attack [%s] to Aggregate switch [%s]",
                        attack, agg_switch.device_id)
            agg_switch.add_attack(**attack)

    def remove_attacker(self, attack, host):
        agg_switch = self.__get_agg_switch()
        if agg_switch:
            agg_switch.stop_attack(**attack)

    def count_dropped_packets(self):
        agg_switch = self.__get_agg_switch()
        if agg_switch:
            return agg_switch.get_drop_pkt_count()
