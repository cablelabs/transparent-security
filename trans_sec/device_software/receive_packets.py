#!/usr/bin/env python3

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
import argparse
import json
import logging
import sys

from scapy.all import bind_layers, sniff
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

import trans_sec.consts
from trans_sec import consts
from trans_sec.packet.inspect_layer import (
    IntShim, IntHeader, IntMeta1, IntMeta2, SourceIntMeta, UdpInt,
    TelemetryReport, EthInt, DropReport)

logger = logging.getLogger('receive_packets')
FORMAT = '%(levelname)s %(asctime)-15s %(filename)s %(message)s'

# global drop_rpt_count
drop_rpt_count = 0
drop_rpt_dict = list()


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-i', '--iface', help='The network interface on which to sniff',
        required=True, dest='iface')
    parser.add_argument(
        '-f', '--logfile', help='File to log to defaults to console',
        required=False, dest='log_file')
    parser.add_argument(
        '-ih', '--int-hops', help='Number of expected INT hops, no INT when 0',
        required=False, default=0, dest='int_hops', type=int)
    parser.add_argument(
        '-dr', '--drop-rpt',
        help='Number of reports to output before exit',
        required=False, default=None, dest='drop_rpt', type=int)
    parser.add_argument(
        '-d', '--duration', default=0, dest='duration', type=int,
        required=False,
        help='Number of seconds to sniff - 0 is indefinite')
    parser.add_argument(
        '-l', '--loglevel',
        help='Log Level <DEBUG|INFO|WARNING|ERROR> defaults to INFO',
        required=False, default='DEBUG', dest='log_level')
    return parser.parse_args()


def __log_packet(packet, int_hops, drop_rpt=None):
    logger.info('Expected INT Hops - [%s] on packet - [%s]',
                int_hops, packet.summary())

    global drop_rpt_count
    ether_pkt = packet[Ether]
    ip_proto = 0
    ip_pkt = None

    if ether_pkt.type == consts.IPV4_TYPE:
        logger.info('Parsing IPv4 packet')
        try:
            ip_pkt = packet[IP]
            ip_proto = ip_pkt.proto
        except Exception:
            logger.debug('Cannot log, not an IPv4 packet - %s',
                         packet.summary())
            return
    elif ether_pkt.type == consts.IPV6_TYPE:
        logger.info('Parsing IPv6 packet')
        try:
            ip_pkt = packet[IPv6]
            ip_proto = ip_pkt.nh
        except Exception:
            logger.debug(
                'Cannot log, not an IPv6 packet - %s with length - [%s]',
                packet.summary(), len(packet))
            return

    logger.info('IP Protocol - [%s] hops - [%s]', ip_proto, int_hops)
    if drop_rpt and ip_proto == trans_sec.consts.UDP_PROTO:
        logger.debug('Attempting to log Drop Report')
        drop_rpt_count += 1
        __log_drop_rpt(ip_pkt, drop_rpt)

    if not drop_rpt:
        if int_hops > 0 and ip_proto == trans_sec.consts.UDP_PROTO:
            logger.debug('Attempting to log INT Packet')
            __log_int_packet(ether_pkt, ip_pkt, int_hops, len(packet))
        elif int_hops < 1:
            logger.debug('Attempting to log Standard Packet')
            __log_std_packet(ether_pkt, ip_pkt, ip_proto, len(packet))
        else:
            logger.debug('Nothing to log here')


def __log_std_packet(ether_pkt, ip_pkt, ip_proto, pkt_len):
    logger.info('Protocol to parse for standard packet - [%s]', ip_proto)
    logger.debug('IP class - [%s]', ip_pkt.__class__)

    if ip_proto == trans_sec.consts.UDP_PROTO:
        logger.info('Parsing UDP Packet')
        tcp_udp_pkt = UDP(_pkt=ip_pkt.payload)
    elif ip_proto == trans_sec.consts.TCP_PROTO:
        logger.info('Parsing TCP Packet')
        tcp_udp_pkt = TCP(_pkt=ip_pkt.payload)
        logger.debug('TCP flags - [%s]', tcp_udp_pkt.flags)
        logger.debug('IP class - [%s]', ip_pkt.__class__)

        # TODO/REMOVE ME once TCP has been fixed as we are currently picking
        #  up resends
        if tcp_udp_pkt.flags != 0x2 and isinstance(ip_pkt, IP):
            logger.debug('TCP flags [%s] not 2, skipping', tcp_udp_pkt.flags)
            return
    else:
        logger.debug('Nothing to log, protocol - [%s] is unsupported',
                     ip_proto)
        return

    int_data = dict(
        eth_src_mac=ether_pkt.src,
        eth_dst_mac=ether_pkt.dst,
        src_ip=ip_pkt.src,
        dst_ip=ip_pkt.dst,
        src_port=tcp_udp_pkt.sport,
        dst_port=tcp_udp_pkt.dport,
        packetLen=pkt_len,
    )

    logger.warning('Packet data - [%s]', int_data)


def __log_drop_rpt(ip_pkt, count_to_exit):
    global drop_rpt_dict

    logger.info('Logging Drop Report packet then exit')
    udp_pkt = UDP(_pkt=ip_pkt.payload)

    if not udp_pkt:
        logger.debug('Packet is not')
        return

    logger.debug('UdpInt - sport - [%s], dport - [%s], len - [%s]',
                 udp_pkt.sport, udp_pkt.dport, udp_pkt.len)
    if udp_pkt.dport == 556:
        drop_rpt_pkt = DropReport(_pkt=udp_pkt.payload)
        if not drop_rpt_dict:
            drop_rpt_dict = dict()
        drop_rpt_dict[drop_rpt_pkt.drop_hash] = drop_rpt_pkt.drop_count

        logger.warning('Drop Report dict - [%s]', drop_rpt_dict)

        if drop_rpt_count >= count_to_exit:
            # Output as json string to stdout
            #  (i.e. for parsing by ansible playbook)
            print(json.dumps(drop_rpt_dict))
            exit(0)


def __log_int_packet(ether_pkt, ip_pkt, int_hops, pkt_len):
    logger.info('Logging INT packet')
    ip_pkt, udp_int_pkt = __get_ip_udp_int_pkt(ip_pkt)
    if not ip_pkt or not udp_int_pkt:
        logger.error('Unable to locate INT UDP Packet')
        return

    logger.debug('UdpInt - sport - [%s], dport - [%s], len - [%s]',
                 udp_int_pkt.sport, udp_int_pkt.dport, udp_int_pkt.len)
    int_shim_pkt = IntShim(_pkt=udp_int_pkt.payload)
    logger.debug('IntShim - next_proto - [%s], length - [%s]',
                 int_shim_pkt.next_proto, int_shim_pkt.length)
    int_hdr_pkt = IntHeader(_pkt=int_shim_pkt.payload)
    logger.debug(
        'INT Header meta_len - [%s] and remaining_hop_cnt - [%s]',
        int_hdr_pkt.meta_len, int_hdr_pkt.remaining_hop_cnt)

    switch_id_2 = None
    switch_id_3 = None
    if int_hops == 1:
        source_int_meta = SourceIntMeta(_pkt=int_hdr_pkt.payload)
        mac1 = source_int_meta.orig_mac
        switch_id_1 = source_int_meta.switch_id
    elif int_hops == 2:
        int_meta_2 = IntMeta2(_pkt=int_hdr_pkt.payload)
        source_int_meta = SourceIntMeta(_pkt=int_meta_2.payload)
        mac1 = source_int_meta.orig_mac
        switch_id_1 = source_int_meta.switch_id
        switch_id_2 = int_meta_2.switch_id
    elif int_hops == 3:
        int_meta_1 = IntMeta1(_pkt=int_hdr_pkt.payload)
        int_meta_2 = IntMeta2(int_meta_1.payload)
        source_int_meta = SourceIntMeta(_pkt=int_meta_2.payload)
        mac1 = source_int_meta.orig_mac
        switch_id_1 = source_int_meta.switch_id
        switch_id_2 = int_meta_2.switch_id
        switch_id_3 = int_meta_1.switch_id
    else:
        raise Exception('No support for hops > 3')

    logger.info('Ether type - [%s]', ether_pkt.type)
    if int_shim_pkt.next_proto == trans_sec.consts.UDP_PROTO:
        logger.info('UDP Packet')
        tcp_udp_packet = UDP(_pkt=source_int_meta.payload)
    else:
        logger.info('TCP Packet')
        tcp_udp_packet = TCP(_pkt=source_int_meta.payload)

    int_data = dict(
        eth_src_mac=ether_pkt.src,
        eth_dst_mac=ether_pkt.dst,
        src_ip=ip_pkt.src,
        dst_ip=ip_pkt.dst,
        mac1=mac1,
        switch_id_1=switch_id_1,
        switch_id_2=switch_id_2,
        switch_id_3=switch_id_3,
        src_port=tcp_udp_packet.sport,
        dst_port=tcp_udp_packet.dport,
        packetLen=pkt_len,
    )
    logger.warning('INT Packet data - [%s]', int_data)


def __get_ip_udp_int_pkt(ip_pkt):
    """
    Retrieves the INT UDP packet
    :param ip_pkt:
    :return:
    """
    logger.info('Obtaining INT data')
    udp_pkt = UDP(_pkt=ip_pkt.payload)
    logger.debug('UDP packet dport - [%s]', udp_pkt.dport)
    if udp_pkt.dport == trans_sec.consts.UDP_INT_DST_PORT:
        logger.debug('Packet is of type INT, returning UDP packet object')
        return ip_pkt, udp_pkt
    elif udp_pkt.dport == trans_sec.consts.UDP_TRPT_DST_PORT:
        logger.debug('Packet is of type Telemetry Report')
        trpt_pkt = TelemetryReport(_pkt=udp_pkt.payload)
        trpt_eth = EthInt(_pkt=trpt_pkt.payload)
        logger.debug('trpt_eth type - [%s]', trpt_eth.type)
        if trpt_eth.type == trans_sec.consts.IPV4_TYPE:
            trpt_ip_pkt = IP(_pkt=trpt_eth.payload)
            logger.debug('IPv4 src - [%s], dst - [%s]',
                         trpt_ip_pkt.src, trpt_ip_pkt.dst)
        elif trpt_eth.type == trans_sec.consts.IPV6_TYPE:
            trpt_ip_pkt = IPv6(_pkt=trpt_eth.payload)
            logger.debug('IPv6 src - [%s], dst - [%s]',
                         trpt_ip_pkt.src, trpt_ip_pkt.dst)
        else:
            raise Exception('Invalid eth type - [{}]'.format(trpt_eth.type))

        return trpt_ip_pkt, UDP(_pkt=trpt_ip_pkt.payload)
    else:
        logger.warning('Invalid INT packet received with dport - [%s]',
                       udp_pkt.dport)
        return None, None


def device_sniff(iface, duration, int_hops, drop_report=None):
    global drop_rpt_count
    if int_hops > 0:
        logger.info('Binding layers for INT with hops - [%s]', int_hops)

        logger.info('Binding Ether -> IP -> UdpInt -> IntShim')
        bind_layers(Ether, IP, type=consts.IPV4_TYPE)
        bind_layers(IP, UdpInt)
        bind_layers(UdpInt, IntShim)
        logger.info('Binding Ether -> IPv6 -> UdpInt -> IntShim')
        bind_layers(Ether, IPv6, type=consts.IPV6_TYPE)
        bind_layers(IPv6, UdpInt)
        bind_layers(UdpInt, IntShim)

        logger.info('Binding IntShim -> IntHeader')
        bind_layers(IntShim, IntHeader)

        if int_hops > 3:
            raise Exception('Cannot currently support more than 3 hops')
    else:
        logger.info('Binding layers for IP')
        bind_layers(Ether, IP, type=consts.IPV4_TYPE)
        bind_layers(IP, UDP)
        bind_layers(IP, TCP)
        bind_layers(Ether, IPv6, type=consts.IPV6_TYPE)
        bind_layers(IPv6, UDP)
        bind_layers(IPv6, TCP)

    logger.info("Sniffing for packets on iface - [%s]", iface)
    if duration > 0:
        logger.info('Running sniffer for [%s] seconds', duration)
        sniff(iface=iface,
              prn=lambda packet: __log_packet(packet, int_hops, drop_report),
              timeout=duration)
    else:
        logger.info('Running sniffer indefinitely')
        sniff(iface=iface,
              prn=lambda packet: __log_packet(packet, int_hops, drop_report))


if __name__ == '__main__':
    args = get_args()
    numeric_level = getattr(logging, args.log_level, None)
    if args.log_file:
        logging.basicConfig(format=FORMAT, level=numeric_level,
                            filename=args.log_file)
    else:
        logging.basicConfig(format=FORMAT, level=numeric_level,
                            stream=sys.stdout)

    logger.info('Logger initialized')
    logger.info('Sniffing for packets on interface - [%s]', args.iface)
    device_sniff(args.iface, args.duration, args.int_hops, args.drop_rpt)
