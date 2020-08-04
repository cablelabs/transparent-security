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

from trans_sec.p4runtime_lib.switch import SwitchConnection
from trans_sec.consts import IPV4_TYPE, IPV6_TYPE
from trans_sec.controller.ddos_sdn_controller import AGG_CTRL_KEY
from trans_sec.utils.convert import decode_num, decode_ipv4

logger = logging.getLogger('bmv2')


class Bmv2SwitchConnection(SwitchConnection, ABC):
    def write_multicast_entry(self, hosts):
        super(Bmv2SwitchConnection, self).write_multicast_entry(hosts)
        self.write_arp_flood()


class GatewaySwitch(Bmv2SwitchConnection):
    def __init__(self, p4info_helper, sw_info, proto_dump_file=None):
        """
        Construct Switch class to control BMV2 switches running gateway.p4
        """
        super(Bmv2SwitchConnection, self).__init__(
            p4info_helper, sw_info, 'TpsGwIngress', 'TpsEgress',
            proto_dump_file)
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
        super(Bmv2SwitchConnection, self).start_digest_listeners()

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
            'switch_id': self.sw_info['id']
        }
        table_entry = self.p4info_helper.build_table_entry(
            table_name='{}.data_inspection_t'.format(self.p4_ingress),
            match_fields={
                'hdr.ethernet.src_mac': dev_mac,
                'hdr.ethernet.etherType': IPV4_TYPE
            },
            action_name='{}.data_inspect_packet_ipv4'.format(
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
            action_name='{}.data_inspect_packet_ipv6'.format(
                self.p4_ingress),
            action_params=action_params)
        self.write_table_entry(table_entry)

        logger.info(
            'Installed Northbound Packet Inspection for device with'
            ' MAC - [%s] with action params - [%s]',
            dev_mac, action_params)

    def add_nat_table(self, udp_source_port, tcp_source_port, source_ip):
        gateway_public_ip = self.sw_info['public_ip']
        logger.info("Adding nat table entries on gateway device [%s] for %s",
                    self.device_id, source_ip)
        logger.info("Check if %s not in %s for %s", udp_source_port,
                    self.nat_udp_ports, self.sw_info['name'])
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
                    'src_port': int("50" + str(self.sw_info['id']) + str(
                        self.udp_port_count)),
                    'ip_srcAddr': gateway_public_ip
                })
            self.write_table_entry(table_entry)
            table_entry = self.p4info_helper.build_table_entry(
                table_name='{}.udp_global_to_local_t'.format(self.p4_ingress),
                match_fields={
                    'hdr.udp.dst_port': int(
                        "50" + str(self.sw_info['id']) + str(
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
                        self.sw_info['name'])
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
                    'src_port': int("50" + str(self.sw_info['id']) + str(
                        self.tcp_port_count)),
                    'ip_srcAddr': gateway_public_ip
                })
            self.write_table_entry(table_entry)
            table_entry = self.p4info_helper.build_table_entry(
                table_name='{}.tcp_global_to_local_t'.format(self.p4_ingress),
                match_fields={
                    'hdr.tcp.dst_port': int(
                        "50" + str(self.sw_info['id']) + str(
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
                        self.sw_info['name'])

    def interpret_nat_digest(self, digest_data):
        logger.debug("Digest data %s", digest_data)
        for members in digest_data:
            logger.debug("Members: %s", members)
            if members.WhichOneof('data') == 'struct':
                udp_source_port = decode_num(
                    members.struct.members[0].bitstring)
                logger.info('Learned UDP Source Port from %s is: %s',
                            self.sw_info['name'], udp_source_port)
                tcp_source_port = decode_num(
                    members.struct.members[1].bitstring)
                logger.info('Learned TCP Source Port from %s is: %s',
                            self.sw_info['name'], tcp_source_port)
                source_ip = decode_ipv4(members.struct.members[2].bitstring)
                logger.info('Learned Source IP Address from %s is: %s',
                            self.sw_info['name'], source_ip)
                self.add_nat_table(udp_source_port, tcp_source_port, source_ip)

    def write_multicast_entry(self, hosts):
        logger.debug('Writing multicast entries on gateway device [%s]',
                     self.device_id)
        super(Bmv2SwitchConnection, self).write_multicast_entry(hosts)

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


class AggregateSwitch(Bmv2SwitchConnection):
    def __init__(self, p4info_helper, sw_info, proto_dump_file=None):
        """
        Construct Switch class to control BMV2 switches running gateway.p4
        """
        super(Bmv2SwitchConnection, self).__init__(
            p4info_helper, sw_info, 'TpsAggIngress', 'TpsEgress',
            proto_dump_file)

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
            'switch_id': self.sw_info['id']
        }
        table_entry = self.p4info_helper.build_table_entry(
            table_name='{}.add_switch_id_t'.format(self.p4_ingress),
            match_fields={
                'hdr.udp.dst_port': 0x022b
            },
            action_name='{}.add_switch_id'.format(
                self.p4_ingress),
            action_params=action_params)
        self.write_table_entry(table_entry)


class CoreSwitch(Bmv2SwitchConnection):
    def __init__(self, p4info_helper, sw_info, proto_dump_file=None):
        """
        Construct Switch class to control BMV2 switches running gateway.p4
        """
        super(Bmv2SwitchConnection, self).__init__(
            p4info_helper, sw_info, 'TpsCoreIngress', 'TpsCoreEgress',
            proto_dump_file)

    def add_data_forward(self, source_mac, ingress_port):
        logger.info(
            'Adding data forward to core device [%s] with source_mac '
            '- [%s] and ingress port - [%s]',
            self.device_id, source_mac, ingress_port)
        inserted = super(Bmv2SwitchConnection, self).add_data_forward(
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

    def add_data_inspection(self, dev_id):
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
                'hdr.udp_int.dst_port': 0x022b
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
