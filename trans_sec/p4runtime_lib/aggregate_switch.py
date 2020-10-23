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
from trans_sec.consts import UDP_INT_DST_PORT
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
            'switch_id': self.int_device_id
        }
        table_entry = self.p4info_helper.build_table_entry(
            table_name='{}.data_inspection_t'.format(self.p4_ingress),
            match_fields={
                'hdr.ethernet.src_mac': dev_mac,
            },
            action_name='{}.data_inspect_packet'.format(
                self.p4_ingress),
            action_params=action_params
        )
        self.write_table_entry(table_entry)

        logger.info(
            'Installed Northbound Packet Inspection for device - [%s]'
            ' with MAC - [%s] with action params - [%s]',
            AGG_CTRL_KEY, dev_mac, action_params)

    def del_data_inspection(self, dev_id, dev_mac):
        logger.info(
            'Adding data inspection to aggregate device [%s] with device ID '
            '- [%s] and mac - [%s]', self.device_id, dev_id, dev_mac)
        # Northbound Traffic Inspection for IPv4
        action_params = {
            'device': dev_id,
            'switch_id': self.int_device_id
        }
        table_entry = self.p4info_helper.build_table_entry(
            table_name='{}.data_inspection_t'.format(self.p4_ingress),
            match_fields={
                'hdr.ethernet.src_mac': dev_mac,
            },
            action_name='{}.data_inspect_packet'.format(
                self.p4_ingress)
        )
        self.delete_table_entry(table_entry)

        logger.info(
            'Installed Northbound Packet Inspection for device - [%s]'
            ' with MAC - [%s] with action params - [%s]',
            AGG_CTRL_KEY, dev_mac, action_params)

    def add_attack(self, **kwargs):
        logger.info('Adding attack [%s]', kwargs)
        action_name, dst_ipv4, dst_ipv6 = self.parse_attack(**kwargs)
        self.insert_p4_table_entry(
            table_name='data_drop_t',
            action_name=action_name,
            match_fields={
                'hdr.ethernet.src_mac': kwargs['src_mac'],
                'meta.ipv4_addr': dst_ipv4,
                'meta.ipv6_addr': dst_ipv6,
                'meta.dst_port': int(kwargs['dst_port']),
            },
            action_params=None,
            ingress_class=True,
         )
        logger.info('%s Dropping TCP Packets from %s',
                    self.name, kwargs.get('src_ip'))

    def stop_attack(self, **kwargs):
        logger.info('Adding attack [%s]', kwargs)
        action_name, dst_ipv4, dst_ipv6 = self.parse_attack(**kwargs)

        self.delete_p4_table_entry(
            table_name='data_drop_t',
            action_name=action_name,
            match_fields={
                'hdr.ethernet.src_mac': kwargs['src_mac'],
                'meta.ipv4_addr': dst_ipv4,
                'meta.ipv6_addr': dst_ipv6,
                'meta.dst_port': int(kwargs['dst_port']),
            },
            ingress_class=True,
         )
        logger.info('%s Dropping TCP Packets from %s',
                    self.name, kwargs.get('src_ip'))

    def add_switch_id(self):
        action_params = {
            'switch_id': self.int_device_id
        }
        table_entry = self.p4info_helper.build_table_entry(
            table_name='{}.add_switch_id_t'.format(self.p4_ingress),
            match_fields={
                'hdr.udp_int.dst_port': UDP_INT_DST_PORT
            },
            action_name='{}.add_switch_id'.format(
                self.p4_ingress),
            action_params=action_params)
        self.write_table_entry(table_entry)

    def drop_count(self):
        pass