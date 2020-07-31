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
from trans_sec.controller.ddos_sdn_controller import GATEWAY_CTRL_KEY
from trans_sec.p4runtime_lib.gateway_switch import GatewaySwitch as P4RTSwitch

logger = getLogger('gateway_controller')

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
                p4info_helper=self.p4info_helper,
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
