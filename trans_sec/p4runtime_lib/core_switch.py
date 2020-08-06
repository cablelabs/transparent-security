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
import socket
from abc import ABC

from trans_sec.consts import UDP_INT_DST_PORT
from trans_sec.p4runtime_lib.p4rt_switch import P4RuntimeSwitch

logger = logging.getLogger('core_switch')


class CoreSwitch(P4RuntimeSwitch):
    def __init__(self, sw_info, proto_dump_file=None):
        """
        Construct Switch class to control BMV2 switches running gateway.p4
        """
        super(self.__class__, self).__init__(
            sw_info, 'TpsCoreIngress', 'TpsCoreEgress', proto_dump_file)

    def write_multicast_entry(self, hosts):
        super(self.__class__, self).write_multicast_entry(hosts)
        self.write_arp_flood()

    def add_data_forward(self, source_mac, ingress_port):
        logger.info(
            'Adding data forward to core device [%s] with source_mac '
            '- [%s] and ingress port - [%s]',
            self.device_id, source_mac, ingress_port)
        inserted = super(self.__class__, self).add_data_forward(
            source_mac, ingress_port)

        if inserted:
            table_entry = self.p4info_helper.build_table_entry(
                table_name='{}.arp_forward_t'.format(self.p4_ingress),
                match_fields={
                    'hdr.ethernet.dst_mac': source_mac
                },
                action_name='{}.arp_forward'.format(self.p4_ingress),
                action_params={'port': ingress_port}
            )
            self.write_table_entry(table_entry)

    def add_data_inspection(self, dev_id, dev_mac):
        logger.info(
            'Adding data inspection entry to core device [%s] with device ID '
            '- [%s]', self.device_id, dev_id)

        action_params = {
            'switch_id': dev_id
        }
        table_name = '{}.data_inspection_t'.format(self.p4_ingress)
        action_name = '{}.data_inspect_packet'.format(self.p4_ingress)
        logger.info(
            'Insert params into table - [%s] for action [%s] '
            'with params [%s] fields [%s] ',
            table_name, action_name, action_params,)
        table_entry = self.p4info_helper.build_table_entry(
            table_name=table_name,
            match_fields={
                'hdr.udp_int.dst_port': UDP_INT_DST_PORT
            },
            action_name=action_name,
            action_params=action_params)
        self.write_table_entry(table_entry)

    def setup_telemetry_rpt(self, ae_ip):
        logger.info(
            'Setting up telemetry report on core device [%s] with '
            'AE IP - [%s]', self.device_id, ae_ip)

        ae_ip_addr = socket.gethostbyname(ae_ip)
        logger.info(
            'Starting telemetry report for INT headers with dst_port '
            'value of 555 to AE IP [%s]', ae_ip_addr)
        table_name = '{}.setup_telemetry_rpt_t'.format(self.p4_egress)
        action_name = '{}.setup_telem_rpt_ipv4'.format(self.p4_egress)
        match_fields = {
            'hdr.udp_int.dst_port': 555
        }
        action_params = {
            'ae_ip': ae_ip_addr
        }
        table_entry = self.p4info_helper.build_table_entry(
            table_name=table_name,
            match_fields=match_fields,
            action_name=action_name,
            action_params=action_params)
        self.write_table_entry(table_entry)
