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
import abc
import datetime
import ipaddress
import logging
import threading
import time

from time import strftime, localtime
from anytree import search, Node, RenderTree
from scapy.all import sniff
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

from trans_sec.consts import (UDP_PROTO, UDP_TRPT_DST_PORT, IPV4_TYPE,
                              UDP_INT_DST_PORT, IPV6_TYPE)
from trans_sec.packet.inspect_layer import (
    IntHeader, IntMeta1, IntMeta2, IntShim, SourceIntMeta, TelemetryReport,
    EthInt, DropReport)
from trans_sec.utils import tps_utils

logger = logging.getLogger('oinc')


class PacketAnalytics(object):
    """
    Analytics Engine class
    """

    def __init__(self, sdn_interface, packet_count=100, sample_interval=60,
                 sdn_attack_context='gwAttack'):
        """
        Constructor
        :param sdn_interface: the HTTP interface to the SDN Controller
        :param packet_count: the number of packets to trigger an attack
        :param sample_interval: the interval in seconds used for counting the
                                packets
        """
        self.sdn_interface = sdn_interface
        self.packet_count = packet_count
        self.sample_interval = sample_interval
        self.count_map = dict()
        self.bytes_map = dict()
        self.sniff_stop = threading.Event()
        self.sdn_attack_context = sdn_attack_context

        logger.debug("Started AE with attack call to [%s/%s]",
                     self.sdn_interface, self.sdn_attack_context)

    def start_sniffing(self, iface, drop_iface=None,
                       udp_dport=UDP_TRPT_DST_PORT):
        """
        Starts the sniffer thread
        :param iface: the interface to sniff for telemetry reports
        :param drop_iface: the interface to sniff for drop reports
        :param udp_dport: the UDP dport to sniff (default 555)
        """
        logger.info('Starting INT packet listener int_thread')
        int_thread = threading.Thread(target=self.sniff_int,
                                      args=(iface, udp_dport))
        int_thread.start()
        logger.debug('int_thread has been started')

        if drop_iface:
            logger.info('Starting Drop Report listener dr_thread')
            dr_thread = threading.Thread(target=self.sniff_drop,
                                         args=(drop_iface, 'foo'))
            dr_thread.start()
            logger.debug('dr_thread has been started')

    def sniff_int(self, iface, udp_port):
        logger.info("INT monitoring iface [%s]", iface)

        try:
            sniff(iface=iface,
                  prn=lambda packet: self.handle_packet(packet, udp_port),
                  stop_filter=lambda p: self.sniff_stop.is_set())
        except Exception as e:
            logger.error('Unexpected error sniffing for INT Data - [%s]', e)
            self.sniff_int(iface, udp_port)

    def sniff_drop(self, iface, foo=None):
        logger.info("Drop monitoring iface [%s]", iface)

        try:
            sniff(iface=iface,
                  prn=lambda packet: self.handle_drop_rpt(packet),
                  stop_filter=lambda p: self.sniff_stop.is_set())
        except Exception as e:
            logger.error('Unexpected error sniffing for Drop Reports - [%s]',
                         e)
            raise e

    def stop_sniffing(self):
        """
        Stops the sniffer thread
        """
        self.sniff_stop.set()

    def handle_packet(self, packet, udp_dport):
        """
        Determines whether or not to process this packet
        :param packet: the packet to process
        :param udp_dport: the UDP protocol dport value to filter
        :return T/F - True when an attack has been triggered
        """
        return self.process_packet(packet, udp_dport)

    def handle_drop_rpt(self, packet):
        """
        Determines whether or not to process this packet
        :param packet: the packet to process
        :return T/F - True when an attack has been triggered
        """
        return self.process_drop_rpt(packet)

    def _send_attack(self, **attack_dict):
        """
        Sends an HTTP POST to the SDN controllers HTTP interface 'attack'
        :param attack_dict: the data to send
        :raises Exception: due to the remote HTTP POST
        """
        logger.info('Start attack - [%s] to [%s]',
                    attack_dict, self.sdn_attack_context)
        self.sdn_interface.post(self.sdn_attack_context, attack_dict)

    def _stop_attack(self, **attack_dict):
        """
        Sends an HTTP POST to the SDN controllers HTTP interface 'attack'
        :param attack_dict: the data to send
        :raises Exception: due to the remote HTTP POST
        """
        logger.info('Stopping attack - [%s] to [%s]',
                    attack_dict, self.sdn_attack_context)
        self.sdn_interface.delete(self.sdn_attack_context, attack_dict)
        logger.info('Attack stopped at time [%s] with args - [%s]',
                    strftime("%b-%d-%Y %H:%M:%S", localtime()), attack_dict)

    @abc.abstractmethod
    def process_packet(self, packet, udp_dport=UDP_INT_DST_PORT):
        """
        Processes a packet to determine if an attack is occurring
        :param packet: the packet to process
        :param udp_dport: the UDP port value on which to filter
        :return: T/F - True when an attack has been triggered
        """
        return

    @abc.abstractmethod
    def process_drop_rpt(self, packet):
        """
        Processes a drop packet to determine if an attack no longer occurring
        :param packet: the packet to process
        :return: T/F - True when an attack should no longer be triggered
        """
        return


def extract_int_data(ether_pkt):
    """
    Parses the required data from the packet
    :param ether_pkt: the packet to parse
    :return: dict with choice header fields extracted
    """
    logger.debug('Extracting packet - [%s]', ether_pkt.summary())
    if ether_pkt.type == IPV4_TYPE:
        ip_pkt = IP(_pkt=ether_pkt.payload)
        logger.debug('IPv4 dst - [%s], src - [%s], proto - [%s]',
                     ip_pkt.dst, ip_pkt.src, ip_pkt.proto)
    elif ether_pkt.type == IPV6_TYPE:
        ip_pkt = IPv6(_pkt=ether_pkt.payload)
        logger.debug('IPv6 dst - [%s], src - [%s], nh - [%s]',
                     ip_pkt.dst, ip_pkt.src, ip_pkt.nh)
    else:
        logger.warning('Unable to process ether type - [%s]', ether_pkt.type)
        return None

    udp_int_pkt = UDP(_pkt=ip_pkt.payload)
    logger.debug('UDP INT sport - [%s], dport - [%s], len - [%s]',
                 udp_int_pkt.sport, udp_int_pkt.dport, udp_int_pkt.len)
    int_shim_pkt = IntShim(_pkt=udp_int_pkt.payload)
    logger.debug('INT Shim next_proto - [%s], npt - [%s], length - [%s]',
                 int_shim_pkt.next_proto, int_shim_pkt.npt,
                 int_shim_pkt.length)
    int_hdr_pkt = IntHeader(_pkt=int_shim_pkt.payload)

    logger.debug('INT Header ver - [%s]', int_hdr_pkt.ver)

    if int_shim_pkt.length == 7:
        source_int_pkt = SourceIntMeta(_pkt=int_hdr_pkt.payload)
    elif int_shim_pkt.length == 8:
        int_meta_1 = IntMeta1(_pkt=int_hdr_pkt.payload)
        logger.debug('INT Meta 1 switch_id - [%s]', int_meta_1.switch_id)
        source_int_pkt = SourceIntMeta(_pkt=int_meta_1.payload)
    elif int_shim_pkt.length == 9:
        int_meta_1 = IntMeta1(_pkt=int_hdr_pkt.payload)
        logger.debug('INT Meta 1 switch_id - [%s]', int_meta_1.switch_id)
        int_meta_2 = IntMeta2(_pkt=int_meta_1.payload)
        logger.debug('INT Meta 2 switch_id - [%s]', int_meta_2.switch_id)
        source_int_pkt = SourceIntMeta(_pkt=int_meta_2.payload)
    else:
        return

    logger.debug('SourceIntMeta switch_id - [%s], orig_mac - [%s]',
                 source_int_pkt.switch_id, source_int_pkt.orig_mac)

    if int_shim_pkt.next_proto == UDP_PROTO:
        tcp_udp_pkt = UDP(_pkt=source_int_pkt.payload)
        logger.debug('TCP sport - [%s], dport - [%s], len - [%s]',
                     tcp_udp_pkt.sport, tcp_udp_pkt.dport, tcp_udp_pkt.len)
    else:
        tcp_udp_pkt = TCP(_pkt=source_int_pkt.payload)
        logger.debug('TCP sport - [%s], dport - [%s]',
                     tcp_udp_pkt.sport, tcp_udp_pkt.dport)

    orig_mac = source_int_pkt.orig_mac

    try:
        out = dict(
            devMac=orig_mac,
            devAddr=ip_pkt.src,
            dstAddr=ip_pkt.dst,
            dstPort=tcp_udp_pkt.dport,
            protocol=int_shim_pkt.next_proto,
            packetLen=len(ether_pkt),
        )
    except Exception as e:
        logger.error('Error extracting header data - %s', e)
        return None
    logger.debug('Extracted header data [%s]', out)
    return out


def extract_trpt_data(udp_packet):
    """
    Parses the required data from the packet
    :param udp_packet: the packet to parse
    :return: dict with choice header fields extracted
    """
    trpt_pkt = TelemetryReport(_pkt=udp_packet.payload)
    trpt_eth = EthInt(trpt_pkt.payload)
    logger.debug('TRPT ethernet dst - [%s], src - [%s], type - [%s]',
                 trpt_eth.dst, trpt_eth.src, trpt_eth.type)
    return extract_int_data(trpt_eth)


def extract_drop_rpt(udp_packet):
    """
    Parses the required data from the packet
    :param udp_packet: the packet to parse
    :return: tuple of key (hash|int) and value (count|int)
    """
    logger.debug('UDP packet sport [%s], dport [%s], len [%s]',
                 udp_packet.sport, udp_packet.dport, udp_packet.len)

    drop_rpt = DropReport(_pkt=udp_packet.payload)
    if drop_rpt:
        return drop_rpt.drop_hash, drop_rpt.drop_count


class Oinc(PacketAnalytics):
    """
    Oinc implementation of PacketAnalytics
    """

    def __init__(self, sdn_interface, packet_count=100, sample_interval=60):
        super(self.__class__, self).__init__(sdn_interface, packet_count,
                                             sample_interval)
        self.tree = Node('root')

    def process_packet(self, packet, udp_dport=UDP_INT_DST_PORT):
        mac, src_ip, dst_ip, dst_port, packet_size = self.__parse_tree(packet)

        if mac:
            if src_ip and dst_ip and dst_port and packet_size:
                self.__packet_with_mac(mac, src_ip, dst_ip, dst_port,
                                       packet_size)
        self.__manage_tree()

    def process_drop_rpt(self, packet):
        pass

    def __parse_tree(self, packet):
        """
        Processes a packet from a new device that has not been counted
        """
        info = extract_int_data(packet[Ether])
        logger.info('Processing packet with info [%s]', info)

        macs = search.findall_by_attr(self.tree, info.get('srcMac'),
                                      name='name', maxlevel=2, maxcount=1)

        mac = None
        src_ip = None
        dst_ip = None
        dst_port = None
        packet_size = None

        if len(macs) > 0:
            mac = macs[0]
            src_ips = search.findall_by_attr(
                mac, info.get('srcIP'), name='name', maxlevel=2, maxcount=1)
            if len(src_ips) != 0:
                src_ip = src_ips[0]
                dst_ips = search.findall_by_attr(
                    src_ip, info.get('dstIP'), name='name', maxlevel=2,
                    maxcount=1)
                if len(dst_ips) != 0:
                    dst_ip = dst_ips[0]
                    logger.info('Processing source IPs - %s', src_ips)
                    dst_ports = search.findall_by_attr(
                        dst_ip, info.get('dstPort'), name='name',
                        maxlevel=2, maxcount=1)
                    if len(dst_ports) != 0:
                        dst_port = dst_ports[0]
                        packet_sizes = search.findall_by_attr(
                            dst_port, info.get('packet_size'),
                            name='name', maxlevel=2, maxcount=1)
                        if len(packet_sizes) != 0:
                            packet_size = packet_sizes[0]

        return mac, src_ip, dst_ip, dst_port, packet_size

    def __manage_tree(self):
        """
        Updates the tree
        I don't think this routine does anything at all
        """
        for pre, fill, node in RenderTree(self.tree):
            if node.name == 'count':
                logger.info(
                    "Tree info %s%s: %s %s p/s attack: %s",
                    pre, node.name, node.value, node.pps, node.attack)
            else:
                logger.info("Pre - [%s], Fill - [%s], Node - [%s]",
                            pre, fill, node.name)

    def __packet_with_mac(self, mac, src_ip, dst_ip, dst_port, packet_size):
        """
        Processes a packet from an existing device that has been counted
        """
        logger.debug('Packet with MAC [%s] and source IP [%s]', mac, src_ip)
        count = packet_size.children[0]
        count.value = count.value + 1
        base_time = count.time
        current_time = datetime.datetime.today()
        delta = (current_time - base_time).total_seconds()
        count.pps = count.value / delta
        if (count.value > 3 and count.pps > 100
                and not count.attack):
            logger.info('UDP Flood attack detected')
            count.attack = True

            # Send to SDN
            try:
                self._send_attack(**dict(
                    src_mac=mac.name,
                    dst_ip=dst_ip.name,
                    dst_port=dst_port.name))
            except Exception as e:
                logger.error('Unexpected error [%s]', e)

        if delta > 60:
            count.time = current_time
            count.value = 1


class SimpleAE(PacketAnalytics):
    """
    Simple implementation of PacketAnalytics where the count for detecting
    attack notifications is based on the unique hash of the extracted INT data
    """

    def __init__(self, sdn_interface, packet_count=100, sample_interval=60,
                 sdn_attack_context='gwAttack', drop_count=3,
                 byte_count=50000):
        super(self.__class__, self).__init__(
            sdn_interface, packet_count, sample_interval, sdn_attack_context)
        # Holds the last time an attack call was issued to the SDN controller
        self.attack_map = dict()
        self.attack_payload = dict()

        # same key as above, value tuple (int, int) first holds the drop count
        # and the second holds the number of drop reports without receiving
        # any associated packets
        self.drop_rpt_map = dict()
        self.drop_count = drop_count
        self.byte_count = byte_count

    def process_packet(self, packet, udp_dport=UDP_INT_DST_PORT):
        """
        Processes a packet to determine if an attack is occurring if the IP
        protocol is as expected
        :param packet: the packet to process
        :param udp_dport: the UDP port value on which to filter
        :return: T/F - True when an attack has been triggered
        """
        ip_pkt, protocol, pkt_bytes = parse_ip_pkt(packet)
        if ip_pkt and protocol and protocol == UDP_PROTO:
            udp_packet = UDP(_pkt=ip_pkt.payload)
            if udp_packet.dport == udp_dport and udp_dport == UDP_INT_DST_PORT:
                int_data = extract_int_data(packet[Ether])
                if int_data:
                    return self.__process(int_data, pkt_bytes)
                else:
                    logger.warning('Unable to debug INT data')
                    return False
            elif (udp_packet.dport == udp_dport
                  and udp_dport == UDP_TRPT_DST_PORT):
                int_data = extract_trpt_data(udp_packet)
                if int_data:
                    return self.__process(int_data, pkt_bytes)
                else:
                    logger.warning('Unable to debug INT data')
                    return False
            else:
                logger.debug(
                    'Cannot process UDP packet dport of - [%s], expected - '
                    '[%s]', udp_packet.dport, udp_dport)
                return False

    def __process(self, int_data, pkt_bytes):
        """
        Processes INT data for analysis
        :param int_data: the data to process
        :return:
        """
        ip_addr = ipaddress.ip_address(int_data['dstAddr'])
        ipv4 = '0.0.0.0'
        ipv6 = '::'
        if ip_addr.version == 4:
            ipv4 = str(ip_addr)
        else:
            ipv6 = str(ip_addr)
        attack_map_key = tps_utils.create_attack_hash(
            mac=int_data['devMac'], port=int_data['dstPort'], ip_addr=ipv4,
            ipv6_addr=ipv6)
        logger.debug('Attack map key - [%s]', attack_map_key)

        if not self.drop_rpt_map.get(attack_map_key):
            logger.debug(
                'Updating drop_rpt_map entry with zeros at time [%s] - [%s]',
                strftime("%b-%d-%Y %H:%M:%S", localtime()), attack_map_key)
            self.drop_rpt_map[attack_map_key] = (0, 0)
        else:
            logger.debug('Creating drop_rpt_map entry with key - [%s]',
                         attack_map_key)
            tuple_val = self.drop_rpt_map[attack_map_key]
            new_tuple = (tuple_val[0], 0)
            self.drop_rpt_map[attack_map_key] = new_tuple

        if not self.count_map.get(attack_map_key):
            self.count_map[attack_map_key] = list()

        curr_time = datetime.datetime.now()
        self.count_map.get(attack_map_key).append((curr_time, pkt_bytes))
        time_bytes_tuple = self.count_map.get(attack_map_key)
        count = 0
        total_bytes = 0
        for eval_time, pkt_bytes in time_bytes_tuple:
            logger.debug('eval_time - [%s], pkt_bytes - [%s]',
                         eval_time, pkt_bytes)
            delta = (curr_time - eval_time).total_seconds()
            if delta > self.sample_interval:
                time_bytes_tuple.remove((eval_time, pkt_bytes))
            else:
                count += 1
                total_bytes += pkt_bytes
        logger.info(
            'Total bytes [%s] and packet count [%s] received in window',
            total_bytes, count)
        if count > self.packet_count or total_bytes > self.byte_count:
            logger.warning(
                'Attack detected at time [%s]- count [%s] & bytes [%s] '
                'with key [%s]',
                strftime("%b-%d-%Y %H:%M:%S", localtime()),
                count, total_bytes, attack_map_key)

            attack_dict = dict(
                src_mac=int_data['devMac'],
                dst_port=int_data['dstPort'],
                dst_ip=int_data['dstAddr'])

            # Send to SDN
            last_attack = self.attack_map.get(attack_map_key)
            if not last_attack or time.time() - last_attack > 1:
                logger.info('Calling SDN, last attack sent - [%s]',
                            last_attack)
                try:
                    self.attack_map[attack_map_key] = time.time()
                    self.attack_payload[attack_map_key] = attack_dict
                    self._send_attack(**attack_dict)
                    return True
                except Exception as e:
                    logger.error('Unexpected error [%s]', e)
                    return False
            else:
                logger.debug(
                    'Not calling SDN as last attack notification for %s'
                    ' was only %s seconds ago',
                    attack_dict, time.time() - last_attack)
                return True
        else:
            logger.debug('No attack detected - count [%s]', count)
            return False

    def process_drop_rpt(self, packet):
        """
        Processes a drop report packet to determine if an attack stopped
        :param packet: the packet to process
        :return: T/F - True when an attack has been triggered
        """
        ip_pkt, protocol, pkt_bytes = parse_ip_pkt(packet)
        if ip_pkt and protocol and protocol == UDP_PROTO:
            udp_packet = UDP(_pkt=ip_pkt.payload)
            if udp_packet.dport == UDP_TRPT_DST_PORT:
                hash_key, drop_count = extract_drop_rpt(udp_packet)
                if self.drop_rpt_map.get(hash_key):
                    tuple_val = self.drop_rpt_map[hash_key]
                    old_count = tuple_val[0]
                    if old_count != drop_count:
                        new_tuple = (drop_count, 0)
                        self.drop_rpt_map[hash_key] = new_tuple
                        return False
                    else:
                        new_tuple = (tuple_val[0], tuple_val[1] + 1)
                        self.drop_rpt_map[hash_key] = new_tuple
                        if new_tuple[1] >= self.drop_count:
                            attack_body = self.attack_payload.get(hash_key)
                            if attack_body:
                                logger.info('Stopping attack with [%s]',
                                            attack_body)
                                self._stop_attack(**attack_body)

                            logger.info('Clearing maps after attacked stopped')
                            self.attack_payload[hash_key] = None
                            self.attack_map[hash_key] = None
                            self.count_map[hash_key] = None
                            self.drop_rpt_map[hash_key] = None
                            logger.info(
                                'Cleared maps with hash [%s] at time [%s]',
                                hash_key, strftime("%b-%d-%Y %H:%M:%S",
                                                   localtime()))
                            return True
                        else:
                            self.drop_rpt_map[hash_key] = new_tuple
                            return False
        return False


def parse_ip_pkt(packet):
    ip_pkt = None
    protocol = None
    pkt_bytes = 0
    try:
        if packet[Ether].type == IPV4_TYPE:
            ip_pkt = IP(_pkt=packet[Ether].payload)
            protocol = ip_pkt.proto
            pkt_bytes = ip_pkt.len
        elif packet[Ether].type == IPV6_TYPE:
            ip_pkt = IPv6(_pkt=packet[Ether].payload)
            protocol = ip_pkt.nh
            pkt_bytes = ip_pkt.plen
    except Exception as e:
        logger.error('Unexpected error processing packet - [%s]', e)

    return ip_pkt, protocol, pkt_bytes


class IntLoggerAE(PacketAnalytics):
    """
    Logs only INT packets
    """

    def process_packet(self, packet, udp_dport=UDP_INT_DST_PORT):
        """
        Logs the INT data within the packet
        :param packet: the INT packet
        :param udp_dport: the UDP port value on which to filter
        :return: False
        """
        logger.info('INT Packet data - [%s]', extract_int_data(packet[Ether]))
        return False

    def process_drop_rpt(self, packet):
        pass


class LoggerAE(PacketAnalytics):
    """
    Logging only
    """

    def handle_packet(self, packet, ip_proto=None):
        """
        Logs every received packet's summary data
        :param packet: extracts data from here
        :param ip_proto: does nothing here
        :return: False
        """
        logger.info('Packet data - [%s]', packet.summary())
        return False

    def process_packet(self, packet, udp_dport=UDP_INT_DST_PORT):
        """
        No need to implement
        :param packet: the packet that'll never come in
        :param udp_dport: the UDP port value on which to filter
        :raises NotImplemented
        """
        raise NotImplemented

    def process_drop_rpt(self, packet):
        pass
