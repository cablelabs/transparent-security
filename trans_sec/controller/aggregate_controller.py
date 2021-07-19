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
from trans_sec.utils import tps_utils

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

        # Holds all of the attacks by the generated attack hash value
        self.attack_dict = {}

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
            
            logger.debug('Creating attack hash')
            attack_hash = tps_utils.create_attack_hash(**attack)

            logger.info('Storing attack [%s] with hash value [%s]',
                        attack, attack_hash)
            if attack_hash not in self.attack_dict:
                self.attack_dict[attack_hash] = attack

    def remove_attacker(self, attack, host):
        self.remove_agg_attacker(attack)

    def remove_agg_attacker(self, attack):
        logger.info('Requesting to remove attacker - [%s]', attack)
        agg_switch = self.__get_agg_switch()
        this_attack = None
        if agg_switch:
            if 'dropKey' in attack:
                drop_key = attack.get('dropKey')
                if drop_key:
                    drop_key_int = int(drop_key[:16], 16)
                    if drop_key_int in self.attack_dict:
                        this_attack = self.attack_dict.pop(drop_key_int)
                        logger.debug('Retrieved this_attack [%s] with key [%s]',
                                    this_attack, drop_key_int)
                    else:
                        logger.warning(
                            'Cannot find attack key with hash - [%s]',
                            drop_key_int)
                        return
                else:
                    logger.warning('Drop key not on request JSON payload')
            else:
                this_attack = attack
                logger.debug('this_attack is the attack [%s]', attack)

            if this_attack:
                agg_switch.stop_attack(**this_attack)

    def count_dropped_packets(self):
        agg_switch = self.__get_agg_switch()
        if agg_switch:
            return agg_switch.get_drop_pkt_counts()
