# Copyright (c) 2020 Cable Television Laboratories, Inc.
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
#
# Originally copied from:
#
# Copyright 2017-present Open Networking Foundation
#
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
#
import logging

from trans_sec.p4runtime_lib.p4rt_switch import P4RuntimeSwitch
from trans_sec.consts import IPV4_TYPE, IPV6_TYPE
from trans_sec.controller.ddos_sdn_controller import AGG_CTRL_KEY

logger = logging.getLogger('aggregate_switch')


class AggregateSwitch(P4RuntimeSwitch):
    def __init__(self, sw_info, proto_dump_file=None):
        """
        Construct Switch class to control BMV2 switches running gateway.p4
        """
        super(self.__class__, self).__init__(
            sw_info, 'TpsAggIngress', 'TpsEgress', proto_dump_file)

    def write_multicast_entry(self, hosts):
        super(self.__class__, self).write_multicast_entry(hosts)
        self.write_arp_flood()

    def add_data_inspection(self, dev_id, dev_mac):
        logger.info(
            'Adding data inspection to aggregate device [%s] with device ID '
            '- [%s] and mac - [%s]', self.device_id, dev_id, dev_mac)
        # Northbound Traffic Inspection for IPv4
        action_params = {
            'device': dev_id,
            'switch_id': self.sw_info['id']
        }
        table_entry = self.p4info_helper.build_table_entry(
            table_name='{}.data_inspection_t'.format(self.p4_ingress),
            match_fields={
                'hdr.ethernet.src_mac': dev_mac,
                'hdr.ethernet.etherType': IPV4_TYPE
            },
            action_name='{}.data_inspect_packet'.format(
                self.p4_ingress),
            action_params=action_params)
        self.write_table_entry(table_entry)

        # Northbound Traffic Inspection for IPv6
        action_params = {
            'device': dev_id,
            'switch_id': self.sw_info['id']
        }
        table_entry = self.p4info_helper.build_table_entry(
            table_name='{}.data_inspection_t'.format(self.p4_ingress),
            match_fields={
                'hdr.ethernet.src_mac': dev_mac,
                'hdr.ethernet.etherType': IPV6_TYPE
            },
            action_name='{}.data_inspect_packet'.format(
                self.p4_ingress),
            action_params=action_params)
        self.write_table_entry(table_entry)
        logger.info(
            'Installed Northbound Packet Inspection for device - [%s]'
            ' with MAC - [%s] with action params - [%s]',
            AGG_CTRL_KEY, dev_mac, action_params)

    def add_switch_id(self, dev_id):
        action_params = {
            'device': dev_id,
            'switch_id': self.sw_info['id']
        }
        table_entry = self.p4info_helper.build_table_entry(
            table_name='{}.add_switch_id_t'.format(self.p4_ingress),
            action_name='{}.add_switch_id'.format(
                self.p4_ingress),
            action_params=action_params)
        self.write_table_entry(table_entry)
