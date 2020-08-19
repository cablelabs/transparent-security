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
import ipaddress
import logging

from trans_sec.p4runtime_lib.p4rt_switch import P4RuntimeSwitch
from trans_sec.consts import UDP_INT_DST_PORT

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

    @staticmethod
    def __parse_attack(**kwargs):
        dst_ip = ipaddress.ip_address(kwargs['dst_ip'])
        action_name = 'data_drop'

        logger.info('Attack dst_ip - [%s]', dst_ip)
        # TODO - Add back source IP address as a match field after adding
        #  mitigation at the Aggregate
        dst_ipv4 = 0
        dst_ipv6 = 0
        if dst_ip.version == 6:
            logger.debug('Attack is IPv6')
            dst_ipv6 = str(dst_ip.exploded)
        else:
            logger.debug('Attack is IPv4')
            dst_ipv4 = str(dst_ip.exploded)

        return action_name, dst_ipv4, dst_ipv6

    def add_attack(self, **kwargs):
        logger.info('Adding attack [%s]', kwargs)
        action_name, dst_ipv4, dst_ipv6 = self.__parse_attack(**kwargs)
        logger.debug("Action name: [%s] , Destination IPv4: [%s] , Destination IPv6: [%s]",
                     action_name, dst_ipv4, dst_ipv6)
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
        action_name, dst_ipv4, dst_ipv6 = self.__parse_attack(**kwargs)

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

    def add_switch_id(self, dev_id):
        action_params = {
            'switch_id': self.sw_info['id']
        }
        table_entry = self.p4info_helper.build_table_entry(
            table_name='{}.add_switch_id_t'.format(self.p4_ingress),
            match_fields={
                'hdr.udp.dst_port': UDP_INT_DST_PORT
            },
            action_name='{}.add_switch_id'.format(
                self.p4_ingress),
            action_params=action_params)
        self.write_table_entry(table_entry)
