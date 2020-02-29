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
import random
import time
from logging import getLogger, basicConfig
from time import sleep

import ipaddress
import yaml
from scapy.all import get_if_list, get_if_hwaddr
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp

# Logger stuff
from trans_sec.packet.inspect_layer import (
    IntShim, IntHeader, IntMeta1, IntMeta2, SourceIntMeta)

logger = getLogger('send_packets')

FORMAT = '%(levelname)s %(asctime)-15s %(filename)s %(message)s'


def get_first_if():
    for iface in get_if_list():
        if iface != 'lo':
            return iface
    raise Exception('No NIC to send packets to')


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-d', '--continuous',
        help='When true, count disregarded and packets will send indefinitely',
        type=bool, required=False, default=False)
    parser.add_argument(
        '-c', '--count', help='Number of packets to send for each burst',
        type=int, default=1, required=False)
    parser.add_argument(
        '-i', '--interval',
        help='How often to send packets in seconds (Default = 1)',
        type=float, required=False, default=1)
    parser.add_argument(
        '-y', '--delay', help='Delay before starting run (Default = 0',
        type=int, required=False, default=0)
    parser.add_argument(
        '-r', '--destination', help='Destination IPv4 address', required=True)
    parser.add_argument(
        '-e', '--src-mac', help='Source MAC Address', required=False,
        default=None)
    parser.add_argument(
        '-sa', '--source-addr', help='Source IP Address', required=False,
        default=None)
    parser.add_argument(
        '-sp', '--source-port', type=int, default=random.randint(49152, 65535),
        help='Source port else it will be random')
    parser.add_argument(
        '-p', '--port', help='Destination port', type=int, required=True)
    parser.add_argument('-m', '--msg', help='Message to send', required=True)
    parser.add_argument(
        '-l', '--loglevel', required=False, default='INFO',
        help='Log Level <DEBUG|INFO|WARNING|ERROR> defaults to INFO')
    parser.add_argument(
        '-f', '--logfile', help='File to log to defaults to console',
        required=False, default=None)
    parser.add_argument(
        '-z', '--interface', required=False, default=None,
        help='Linux named ethernet device. Defaults to first one found')
    parser.add_argument(
        '-s', '--switch_ethernet',
        help='Switch Ethernet Interface. Defaults to ff:ff:ff:ff:ff:ff',
        required=False, default='ff:ff:ff:ff:ff:ff')
    parser.add_argument(
        '-ih', '--int-hdr-file', required=False,
        help='Switch Ethernet Interface. Defaults to ff:ff:ff:ff:ff:ff')
    parser.add_argument(
        '-it', '--iterations',
        help='Number of iterations of packet groups to send',
        required=False, default=1, type=int)
    parser.add_argument(
        '-itd', '--iter-delay',
        help='Seconds between iterations of packet groups to be sent',
        required=False, default=1, type=int)
    parser.add_argument(
        '-pr', '--protocol', dest='protocol', required=False, type=str,
        default='UDP', choices=['TCP', 'UDP'],
        help='The packet protocol to generate. [TCP|UDP - default]')
    args = parser.parse_args()
    return args


def device_send(args):
    logger.info('Begin sending packets')

    interface = args.interface
    if not interface:
        interface = get_first_if()
    logger.info('Sending packets to intf - [%s]', args.interface)

    logger.info('Delaying %d seconds' % args.delay)
    sleep(args.delay)

    pkt = __create_packet(args, interface)
    if args.continuous:
        logger.info('Sending a packet to %s every %s',
                    interface, args.interval)
        sendp(pkt, iface=interface, verbose=2, inter=args.interval, loop=1)
    else:
        logger.info('Starting iter loop for iterations %s', args.iterations)
        for i in range(0, args.iterations):
            logger.info('Iteration %s', i)
            logger.info('Sending %s packets to %s every %s',
                        args.count, interface, args.interval)
            sendp(pkt, iface=interface, verbose=2, count=args.count,
                  inter=args.interval)
            time.sleep(args.iter_delay)

    logger.info('Done')
    return


def __create_packet(args, interface):
    logger.info('Send to destination - [%s]', args.destination)

    src_mac = args.src_mac
    if not src_mac:
        src_mac = get_if_hwaddr(interface)
    logger.info('Device mac - [%s]', src_mac)

    ip_ver = 4
    ip_addr = ipaddress.ip_address(unicode(args.destination))
    logger.info('Destination IP addr [%s] ([%s]) type - [%s]',
                args.destination, args.destination, ip_addr.__class__)
    if isinstance(ip_addr, ipaddress.IPv6Address):
        ip_ver = 6
    logger.info('IP version is - [%s]', ip_ver)

    if args.int_hdr_file:
        int_data = __read_yaml_file(args.int_hdr_file)
        logger.info('Int data to add to packet - [%s]', int_data)
        ip_len = 34 + (int(int_data['shim']['length'])*4)
        if ip_ver == 4:
            pkt = (Ether(src=src_mac, dst=args.switch_ethernet, type=0x0800) /
                   IP(dst=args.destination, src=args.source_addr, len=ip_len,
                      proto=0xfd))
        else:
            pkt = (Ether(src=src_mac, dst=args.switch_ethernet, type=0x86dd) /
                   IPv6(dst=args.destination, src=args.source_addr, nh=0xfd))

        if args.protocol == 'UDP':
            pkt = pkt / IntShim(length=int(int_data['shim']['length']),
                                next_proto=0x11)
        elif args.protocol == 'TCP':
            pkt = pkt / IntShim(length=int(int_data['shim']['length']),
                                next_proto=0x06)

        int_hops = len(int_data['meta'])
        if int_hops > 0:
            meta_len = 1
            if int_hops == 1:
                meta_len = 3
            pkt = pkt / IntHeader(meta_len=meta_len)
            ctr = 0
            for int_meta in int_data['meta']:
                logger.info('Adding int_meta - [%s] to INT data', int_meta)

                if ctr == 0 and not int_meta.get('orig_mac'):
                    logger.info('Adding IntMeta1')
                    pkt = pkt / IntMeta1(switch_id=int_meta['switch_id'])
                elif ctr > 0 and not int_meta.get('orig_mac'):
                    logger.info('Adding IntMeta2')
                    pkt = pkt / IntMeta2(switch_id=int_meta['switch_id'])
                elif int_meta.get('orig_mac'):
                    orig_mac = int_meta.get('orig_mac')
                    logger.info('Adding Source INT Meta with orig_mac - [%s]',
                                orig_mac)
                    pkt = pkt / SourceIntMeta(
                        switch_id=int_meta['switch_id'],
                        orig_mac=orig_mac)
                ctr += 1
    else:
        if ip_ver == 4:
            if args.protocol == 'TCP':
                ip_hdr = IP(dst=args.destination, src=args.source_addr,
                            proto=0x06)
            elif args.protocol == 'UDP':
                ip_hdr = IP(dst=args.destination, src=args.source_addr,
                            proto=0x11)
        else:
            if args.protocol == 'TCP':
                ip_hdr = IPv6(dst=args.destination, src=args.source_addr,
                              nh=0x06)
            elif args.protocol == 'UDP':
                ip_hdr = IPv6(dst=args.destination, src=args.source_addr,
                              nh=0x11)
        pkt = Ether(src=src_mac, dst=args.switch_ethernet) / ip_hdr

    logger.info('Packet to emit - [%s]', pkt.summary())

    if args.protocol == 'TCP':
        logger.info('Generating a TCP packet')
        pkt = pkt / TCP(dport=args.port, sport=args.source_port)
    elif args.protocol == 'UDP':
        logger.info('Generating a UDP packet')
        pkt = pkt / UDP(dport=args.port, sport=args.source_port)

    return pkt / args.msg


def __read_yaml_file(config_file_path):
    """
    Reads a yaml file and returns a dict representation of it
    :return: a dict of the yaml file
    """
    logger.debug('Attempting to load configuration file - ' + config_file_path)
    config_file = None
    try:
        with open(config_file_path, 'r') as config_file:
            config = yaml.safe_load(config_file)
            logger.info('Loaded configuration')
        return config
    finally:
        if config_file:
            logger.info('Closing configuration file')
            config_file.close()


if __name__ == '__main__':
    cmd_args = get_args()
    numeric_level = getattr(logging, cmd_args.loglevel.upper(), None)
    if cmd_args.logfile:
        basicConfig(format=FORMAT, level=numeric_level,
                    filename=cmd_args.logfile)
    else:
        basicConfig(format=FORMAT, level=numeric_level)

    logger.info('Starting Send with args - [%s]', cmd_args)
    device_send(cmd_args)
