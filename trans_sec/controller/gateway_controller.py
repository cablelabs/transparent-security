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
import ipaddress
from logging import getLogger
from trans_sec.controller.abstract_controller import AbstractController
from trans_sec.controller.ddos_sdn_controller import GATEWAY_CTRL_KEY

logger = getLogger('gateway_controller')

try:
    from trans_sec.p4runtime_lib.gateway_switch import (
        GatewaySwitch as P4RTSwitch)
except Exception as e:
    logger.warning(
        "Error [%s] - while attempting to import "
        "trans_sec.p4runtime_lib.aggregate_switch.AggregateSwitch", e)

try:
    from trans_sec.bfruntime_lib.gateway_switch import (
        GatewaySwitch as BFRTSwitch)
except Exception as e:
    logger.warning(
        "Error [%s] - while attempting to import "
        "trans_sec.bfruntime_lib.aggregate_switch.AggregateSwitch", e)

try:
    from trans_sec.p4runtime_lib.gateway_switch import (
        GatewaySwitch as P4RTSwitch)
except Exception as e:
    logger.warning(
        "Error [%s] - while attempting to import "
        "trans_sec.p4runtime_lib.gateway_switch.GatewaySwitch", e)

try:
    from trans_sec.bfruntime_lib.gateway_switch import (
        GatewaySwitch as BFRTSwitch)
except Exception as e:
    logger.warning('Could not import bfrt classes')


class GatewayController(AbstractController):
    """
    Implementation of the controller for a switch running the gateway.p4
    program
    """
    def __init__(self, platform, p4_build_out, topo, log_dir, load_p4=True):
        super(self.__class__, self).__init__(
            platform, p4_build_out, topo, GATEWAY_CTRL_KEY, log_dir, load_p4)

    def instantiate_switch(self, sw_info):
        if 'arch' in sw_info and sw_info['arch'] == 'tna':
            return BFRTSwitch(sw_info=sw_info)
        else:
            return P4RTSwitch(
                sw_info=sw_info,
                proto_dump_file='{}/{}-switch-controller.log'.format(
                    self.log_dir, sw_info['name']))

    def make_rules(self, sw, north_facing_links, south_facing_links,
                   add_di):
        """
        Overrides the abstract method from super
        :param sw: switch object
        :param north_facing_links: northbound links
        :param south_facing_links: southbound links
        :param add_di: when True inserts into the data_inspection_t table
        """
        for device_link in south_facing_links:
            device = self.topo['hosts'].get(device_link['south_node'])

            if device:
                logger.info('Gateway: ' + sw.name +
                            ' connects to Device: ' + device['name'] +
                            ' on physical port ' +
                            str(device_link.get('south_facing_port')) +
                            ' to IP ' + device.get('ip') +
                            ':' + str(device.get('ip_port')))

                if add_di:
                    sw.add_data_inspection(dev_id=device['id'],
                                           dev_mac=device['mac'])

    def __process_gw_attack(self, attack, host):
        attack_switch = None
        for switch in self.switches:
            if switch.type == 'gateway':
                di_match_mac = switch.get_data_inspection_src_mac_keys()
                if len(di_match_mac) > 0:
                    logger.debug(
                        'Data inspection table keys on device [%s] - [%s]',
                        switch.sw_info['id'], di_match_mac)
                    if attack['src_mac'] in di_match_mac:
                        logger.info('Found source switch - [%s]', switch.name)
                        attack_switch = switch
                else:
                    attack_switch = self.switches[0]
                    break
        if attack_switch:
            logger.info('Adding an attack [%s] to host [%s] and switch [%s]',
                        attack, host, attack_switch.name)
            ip_addr = ipaddress.ip_address(attack['src_ip'])
            logger.info('Attack ip addr - [%s]', ip_addr)
            logger.debug('Attack ip addr class - [%s]', ip_addr.__class__)
            if ip_addr.version == 6:
                logger.debug('Attack is IPv6')
                proto_key = 'ipv6'
            else:
                logger.debug('Attack is IPv4')
                proto_key = 'ipv4'

            dst_addr_key = 'hdr.{}.dstAddr'.format(proto_key)
            return attack_switch, dst_addr_key
        else:
            return None

    def add_attacker(self, attack, host):
        logger.info('Attack received by the controller of type [%s] - [%s]',
                    self.switch_type, attack)
        attack_switch, dst_addr_key = self.__process_gw_attack(attack, host)
        if attack_switch and dst_addr_key:
            attack['host'] = host
            attack[dst_addr_key] = attack['src_ip']
            attack_switch.add_attack(**attack)

    def remove_attacker(self, attack, host):
        attack_switch, dst_addr_key = self.__process_gw_attack(attack, host)
        if attack_switch and dst_addr_key:
            attack['host'] = host
            attack[dst_addr_key] = attack['src_ip']
            attack_switch.stop_attack(**attack)

    def count_dropped_packets(self):
        pass
