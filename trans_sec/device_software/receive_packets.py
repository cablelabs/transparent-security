#!/usr/bin/env python

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
import logging

from scapy.all import bind_layers, sniff
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

from trans_sec.analytics import oinc
from trans_sec.packet.inspect_layer import (
    IntShim, IntHeader, IntMeta1, IntMeta2, SourceIntMeta, UdpInt)

logger = logging.getLogger('receive_packets')
FORMAT = '%(levelname)s %(asctime)-15s %(filename)s %(message)s'


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-i', '--iface', help='The network interface on which to sniff',
        required=True, dest='iface')
    parser.add_argument(
        '-f', '--logfile', help='File to log to defaults to console',
        required=False, dest='log_file')
    parser.add_argument(
        '-v', '--ip-ver', help='The IP version to parse (4|6) default 4',
        required=False, default=4, dest='ip_ver', choices=[4, 6], type=int)
    parser.add_argument(
        '-ih', '--int-hops', help='Number of expected INT hops, no INT when 0',
        required=False, default=0, dest='int_hops', type=int)
    parser.add_argument(
        '-d', '--duration', default=0, dest='duration', type=int,
        help='Number of seconds to sniff - 0 is indefinite')
    parser.add_argument(
        '-l', '--loglevel',
        help='Log Level <DEBUG|INFO|WARNING|ERROR> defaults to INFO',
        required=False, default='INFO', dest='log_level')
    return parser.parse_args()


def __log_packet(packet, int_hops, ip_ver):
    logger.info('Expected INT Hops - [%s] on packet - [%s]',
                int_hops, packet.summary())

    ip_proto = None

    if ip_ver == 4:
        try:
            ip_proto = packet[IP].proto
        except Exception:
            logger.debug('Cannot log, not an IPv4 packet - %s',
                         packet.summary())
    else:
        try:
            ip_proto = packet[IPv6].nh
        except Exception:
            logger.debug('Cannot log, not an IPv6 packet - %s',
                         packet.summary())

    if int_hops > 0 and ip_proto == oinc.INT_PROTO:
        logger.debug('INT Packet received')

        mac1 = None
        switch_id_1 = None
        switch_id_2 = None
        switch_id_3 = None
        if int_hops == 1:
            source_int_meta = SourceIntMeta(_pkt=packet[IntHeader].payload)
            mac1 = source_int_meta.orig_mac
            switch_id_1 = source_int_meta.switch_id
        if int_hops == 2:
            int_meta_2 = IntMeta2(_pkt=packet[IntHeader].payload)
            source_int_meta = SourceIntMeta(_pkt=int_meta_2.payload)
            mac1 = source_int_meta.orig_mac
            switch_id_1 = source_int_meta.switch_id
            switch_id_2 = int_meta_2.switch_id
        if int_hops == 3:
            int_meta_1 = IntMeta1(_pkt=packet[IntHeader].payload)
            int_meta_2 = IntMeta2(_pkt=packet[IntHeader].payload)
            source_int_meta = SourceIntMeta(_pkt=int_meta_2.payload)
            mac1 = source_int_meta.orig_mac
            switch_id_1 = source_int_meta.switch_id
            switch_id_2 = int_meta_2.switch_id
            switch_id_3 = int_meta_1.switch_id

        logger.info('Ether type - [%s]', packet[Ether].type)
        if packet[Ether].type == oinc.IPV4_TYPE:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        else:
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst

        src_port = packet[UdpInt].sport
        dst_port = packet[UdpInt].dport

        logger.info('src port - [%s], dst_port - [%s]', src_port, dst_port)

        int_data = dict(
            eth_src_mac=packet[Ether].src,
            eth_dst_mac=packet[Ether].dst,
            src_ip=src_ip,
            dst_ip=dst_ip,
            mac1=mac1,
            switch_id_1=switch_id_1,
            switch_id_2=switch_id_2,
            switch_id_3=switch_id_3,
            src_port=src_port,
            dst_port=dst_port,
            packetLen=len(packet),
        )
        logger.warn('INT Packet data - [%s]', int_data)
    elif int_hops < 1 and ip_proto != oinc.INT_PROTO:
        logger.info('Non INT Packet received - [%s]', packet.summary())

        if packet[Ether].type == oinc.IPV4_TYPE:
            logger.info('Parsing IPv4 packet')
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
        else:
            logger.info('Parsing IPv6 packet')
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst

        try:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        except Exception:
            try:
                src_port = packet[TCP].sport
                dst_port = packet[TCP].dport
            except Exception:
                logger.debug(
                    'Unsupported packet received - [%s]', packet.summary())
                return

        int_data = dict(
            eth_src_mac=packet[Ether].src,
            eth_dst_mac=packet[Ether].dst,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            packetLen=len(packet),
        )

        logger.warn('Packet data - [%s]', int_data)
    else:
        logger.debug('Nothing to log here')


def device_sniff(iface, duration, int_hops, ip_ver):
    if int_hops > 0:
        logger.info('Binding layers for INT with hops - [%s]', int_hops)

        if ip_ver == 4:
            logger.info('Binding Ether -> IP -> UdpInt -> IntShim')
            bind_layers(Ether, IP)
            bind_layers(IP, UdpInt)
            bind_layers(UdpInt, IntShim)
        else:
            logger.info('Binding Ether -> IPv6 -> UdpInt -> IntShim')
            bind_layers(Ether, IPv6)
            bind_layers(IPv6, UdpInt)
            bind_layers(UdpInt, IntShim)

        logger.info('Binding IntShim -> IntHeader')
        bind_layers(IntShim, IntHeader)

        if int_hops > 3:
            raise Exception('Cannot currently support more than 3 hops')
    else:
        logger.info('Binding layers for IP')
        if ip_ver == 4:
            bind_layers(Ether, IP)
            bind_layers(IP, UDP)
            bind_layers(IP, TCP)
        else:
            bind_layers(Ether, IPv6)
            bind_layers(IPv6, UDP)
            bind_layers(IPv6, TCP)

    logger.info("Sniffing for packets on iface - [%s]", iface)
    if duration > 0:
        logger.info('Running sniffer for [%s] seconds', duration)
        sniff(iface=iface,
              prn=lambda packet: __log_packet(packet, int_hops, ip_ver),
              timeout=duration)
    else:
        logger.info('Running sniffer indefinitely')
        sniff(iface=iface,
              prn=lambda packet: __log_packet(packet, int_hops, ip_ver))


if __name__ == '__main__':
    args = get_args()

    numeric_level = getattr(logging, args.log_level, None)
    if args.log_file:
        logging.basicConfig(format=FORMAT, level=numeric_level,
                            filename=args.log_file)
    else:
        logging.basicConfig(format=FORMAT, level=numeric_level)

    logger.info('Logger initialized')

    device_sniff(args.iface, args.duration, args.int_hops, args.ip_ver)
