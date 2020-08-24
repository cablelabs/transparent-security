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
from abc import ABC

from trans_sec.consts import IPV6_TYPE, IPV4_TYPE
from trans_sec.p4runtime_lib.p4rt_switch import P4RuntimeSwitch
from trans_sec.utils.convert import decode_num, decode_ipv4

logger = logging.getLogger('gateway_switch')


class GatewaySwitch(P4RuntimeSwitch, ABC):
    def __init__(self, sw_info, proto_dump_file=None):
        """
        Construct Switch class to control BMV2 switches running gateway.p4
        """
        super(self.__class__, self).__init__(
            sw_info, 'TpsGwIngress', 'TpsEgress', proto_dump_file)
        self.nat_udp_ports = set()
        self.nat_tcp_ports = set()
        self.tcp_port_count = 1
        self.udp_port_count = 1

    def start_digest_listeners(self):
        logger.debug('Starting digest listener for - [%s]', self.sw_info)
        if 'arch' in self.sw_info and self.sw_info.get('arch') == 'tofino':
            logger.info('Tofino currently not supporting digests')
            pass
        else:
            logger.info('Building digest entry')
            digest_entry, digest_info = self.p4info_helper.build_digest_entry(
                digest_name="nat_digest")
            self.write_digest_entry(digest_entry)
        super(self.__class__, self).start_digest_listeners()

    def receive_nat_digests(self):
        """
        Runnable method for self.digest_thread
        """
        logger.info("Started listening NAT digest thread for %s",
                    self.name)
        while True:
            try:
                logger.debug('Requesting NAT digests')
                digests = self.digest_list()
                digest_data = digests.digest.data
                self.interpret_nat_digest(digest_data)
                logger.debug('Interpreted NAT digest data')
            except Exception as e:
                logger.error(
                    'Unexpected error reading NAT digest from [%s] - [%s]',
                    self.name, e)

    def add_data_inspection(self, dev_id, dev_mac):
        logger.info(
            'Adding data inspection to gateway device [%s] with device ID '
            '- [%s] and mac - [%s]', self.device_id, dev_id, dev_mac)
        # Northbound Traffic Inspection for IPv4
        action_params = {
            'device': dev_id,
            'switch_id': self.device_id
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
            'Installed Northbound Packet Inspection for device with'
            ' MAC - [%s] with action params - [%s]',
            dev_mac, action_params)

    def del_data_inspection(self, dev_id, dev_mac):
        logger.info(
            'Adding data inspection to gateway device [%s] with device ID '
            '- [%s] and mac - [%s]', self.device_id, dev_id, dev_mac)
        # Northbound Traffic Inspection for IPv4
        action_params = {
            'device': dev_id,
            'switch_id': self.device_id
        }
        table_entry = self.p4info_helper.build_table_entry(
            table_name='{}.data_inspection_t'.format(self.p4_ingress),
            match_fields={
                'hdr.ethernet.src_mac': dev_mac,
            },
            action_name='{}.data_inspect_packet'.format(
                self.p4_ingress),
        )
        self.delete_table_entry(table_entry)

        logger.info(
            'Installed Northbound Packet Inspection for device with'
            ' MAC - [%s] with action params - [%s]',
            dev_mac, action_params)

    @staticmethod
    def __parse_attack(**kwargs):
        src_ip = ipaddress.ip_address(kwargs['src_ip'])
        dst_ip = ipaddress.ip_address(kwargs['dst_ip'])
        udp_table_name = 'data_drop_udp_ipv{}_t'.format(dst_ip.version)
        tcp_table_name = 'data_drop_tcp_ipv{}_t'.format(dst_ip.version)
        action_name = 'data_drop'

        logger.info('Attack src_ip - [%s], dst_ip - [%s]', src_ip, dst_ip)
        # TODO - Add back source IP address as a match field after adding
        #  mitigation at the Aggregate
        if dst_ip.version == 6:
            logger.debug('Attack is IPv6')
            proto_key = 'ipv6'
        else:
            logger.debug('Attack is IPv4')
            proto_key = 'ipv4'

        dst_addr_key = 'hdr.{}.dstAddr'.format(proto_key)

        out = (udp_table_name, tcp_table_name, action_name,
               str(dst_ip.exploded), dst_addr_key)
        logger.info('Attack data - [%s]', out)
        return out

    def add_attack(self, **kwargs):
        logger.info('Adding attack [%s]', kwargs)
        udp_tn, tcp_tn, action_name, dst_ip, dst_addr_key = \
            self.__parse_attack(**kwargs)

        self.insert_p4_table_entry(
            table_name=udp_tn,
            action_name=action_name,
            match_fields={
                'hdr.ethernet.src_mac': kwargs['src_mac'],
                dst_addr_key: str(dst_ip),
                'hdr.udp.dst_port': int(kwargs['dst_port']),
            },
            action_params={'device': self.device_id},
            ingress_class=True,
         )
        logger.info('%s Dropping UDP Packets from %s',
                    self.name, kwargs.get('src_ip'))
        self.insert_p4_table_entry(
            table_name=tcp_tn,
            action_name=action_name,
            match_fields={
                'hdr.ethernet.src_mac': kwargs['src_mac'],
                dst_addr_key: str(dst_ip),
                'hdr.tcp.dst_port': int(kwargs['dst_port']),
            },
            action_params={'device': self.device_id},
            ingress_class=True,
         )
        logger.info('%s Dropping TCP Packets from %s',
                    self.name, kwargs.get('src_ip'))

    def stop_attack(self, **kwargs):
        logger.info('Stopping attack [%s]', kwargs)
        udp_tn, tcp_tn, action_name, dst_ip, dst_addr_key = \
            self.__parse_attack(**kwargs)

        self.delete_p4_table_entry(
            table_name=udp_tn,
            action_name=action_name,
            match_fields={
                'hdr.ethernet.src_mac': kwargs['src_mac'],
                dst_addr_key: dst_ip,
                'hdr.udp.dst_port': int(kwargs['dst_port']),
            },
            ingress_class=True,
         )
        logger.info('%s no longer dropping UDP Packets from %s',
                    self.name, kwargs.get('src_ip'))
        self.delete_p4_table_entry(
            table_name=tcp_tn,
            action_name=action_name,
            match_fields={
                'hdr.ethernet.src_mac': kwargs['src_mac'],
                dst_addr_key: dst_ip,
                'hdr.tcp.dst_port': int(kwargs['dst_port']),
            },
            ingress_class=True,
         )
        logger.info('%s no longer dropping TCP Packets from %s',
                    self.name, kwargs.get('src_ip'))

    def add_nat_table(self, udp_source_port, tcp_source_port, source_ip):
        gateway_public_ip = self.sw_info['public_ip']
        logger.info("Adding nat table entries on gateway device [%s] for %s",
                    self.device_id, source_ip)
        logger.info("Check if %s not in %s for %s", udp_source_port,
                    self.nat_udp_ports, self.name)
        # NAT Table Entries to handle UDP packets
        if udp_source_port and udp_source_port not in self.nat_udp_ports:
            table_entry = self.p4info_helper.build_table_entry(
                table_name='{}.udp_local_to_global_t'.format(self.p4_ingress),
                match_fields={
                    'hdr.udp.src_port': udp_source_port,
                    'hdr.ipv4.srcAddr': (source_ip, 32)
                },
                action_name='{}.udp_local_to_global'.format(self.p4_ingress),
                action_params={
                    'src_port': int("50" + str(self.device_id) + str(
                        self.udp_port_count)),
                    'ip_srcAddr': gateway_public_ip
                })
            self.write_table_entry(table_entry)
            table_entry = self.p4info_helper.build_table_entry(
                table_name='{}.udp_global_to_local_t'.format(self.p4_ingress),
                match_fields={
                    'hdr.udp.dst_port': int(
                        "50" + str(self.device_id) + str(
                            self.udp_port_count)),
                    'hdr.ipv4.dstAddr': (gateway_public_ip, 32)
                },
                action_name='{}.udp_global_to_local'.format(self.p4_ingress),
                action_params={
                    'dst_port': udp_source_port,
                    'ip_dstAddr': source_ip
                })
            self.write_table_entry(table_entry)
            self.udp_port_count = self.udp_port_count + 1
            self.nat_udp_ports.add(udp_source_port)
            logger.info("UDP NAT table entry added on %s",
                        self.name)
        elif tcp_source_port and tcp_source_port not in self.nat_tcp_ports:
            # NAT Table Entries to handle TCP packets
            table_entry = self.p4info_helper.build_table_entry(
                table_name='{}.tcp_local_to_global_t'.format(self.p4_ingress),
                match_fields={
                    'hdr.tcp.src_port': tcp_source_port,
                    'hdr.ipv4.srcAddr': (source_ip, 32)
                },
                action_name='{}.tcp_local_to_global'.format(self.p4_ingress),
                action_params={
                    'src_port': int("50" + str(self.device_id) + str(
                        self.tcp_port_count)),
                    'ip_srcAddr': gateway_public_ip
                })
            self.write_table_entry(table_entry)
            table_entry = self.p4info_helper.build_table_entry(
                table_name='{}.tcp_global_to_local_t'.format(self.p4_ingress),
                match_fields={
                    'hdr.tcp.dst_port': int(
                        "50" + str(self.device_id) + str(
                            self.tcp_port_count)),
                    'hdr.ipv4.dstAddr': (gateway_public_ip, 32)
                },
                action_name='{}.tcp_global_to_local'.format(self.p4_ingress),
                action_params={
                    'dst_port': tcp_source_port,
                    'ip_dstAddr': source_ip
                })
            self.write_table_entry(table_entry)
            self.tcp_port_count = self.tcp_port_count + 1
            self.nat_tcp_ports.add(tcp_source_port)
            logger.info("TCP NAT table entry added on %s",
                        self.name)

    def interpret_nat_digest(self, digest_data):
        logger.debug("Digest data %s", digest_data)
        for members in digest_data:
            logger.debug("Members: %s", members)
            if members.WhichOneof('data') == 'struct':
                udp_source_port = decode_num(
                    members.struct.members[0].bitstring)
                logger.info('Learned UDP Source Port from %s is: %s',
                            self.name, udp_source_port)
                tcp_source_port = decode_num(
                    members.struct.members[1].bitstring)
                logger.info('Learned TCP Source Port from %s is: %s',
                            self.name, tcp_source_port)
                source_ip = decode_ipv4(members.struct.members[2].bitstring)
                logger.info('Learned Source IP Address from %s is: %s',
                            self.name, source_ip)
                self.add_nat_table(udp_source_port, tcp_source_port, source_ip)

    def write_multicast_entry(self, hosts):
        logger.debug('Writing multicast entries on gateway device [%s]',
                     self.device_id)
        super(self.__class__, self).write_multicast_entry(hosts)

        # TODO/FIXME - We need to define something in the topology for
        #  determining which is the NB server as this will break outside of
        #  the tested topologies and probably has other unintended consequences
        target_host = None

        logger.debug('Switch Hosts defs - [%s]', hosts)

        for host in hosts.values():
            logger.debug('Switch Host def - [%s]', host)
            if host['type'] == 'target-server':
                target_host = host

        if target_host:
            table_entry = self.p4info_helper.build_table_entry(
                table_name='{}.mac_lookup_ipv4_t'.format(self.p4_ingress),
                match_fields={
                    'hdr.ipv4.dstAddr': (target_host['ip'], 32)
                },
                action_name='{}.mac_lookup'.format(self.p4_ingress),
                action_params={
                    'dst_mac': target_host['mac']
                })
            self.write_table_entry(table_entry)
            table_entry = self.p4info_helper.build_table_entry(
                table_name='{}.mac_lookup_ipv6_t'.format(self.p4_ingress),
                match_fields={
                    'hdr.ipv6.dstAddr': (target_host['ipv6'], 128)
                },
                action_name='{}.mac_lookup'.format(self.p4_ingress),
                action_params={
                    'dst_mac': target_host['mac']
                })
            self.write_table_entry(table_entry)
        else:
            logger.warning('Target host not found, not setting the '
                           'multicast group')
