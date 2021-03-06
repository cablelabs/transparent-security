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
import socket
from logging import getLogger, basicConfig
from time import sleep

from scapy.all import get_if_list, get_if_hwaddr, get_if_addr
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp

# Logger stuff
logger = getLogger('send')

FORMAT = '%(levelname)s %(asctime)-15s %(filename)s %(message)s'


def get_if(target):
    iface = None
    logger.error(target)
    for i in get_if_list():
        logger.info(i.find(target))
        if i.find(target) >= 0:
            iface = i
            break
    if not iface:
        logger.error('Cannot find %s interface' % target)
        exit(1)
    return iface


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--duration', help='Number of seconds to run',
                        type=int, required=True)
    parser.add_argument('-i', '--interval',
                        help='How often to send packets in seconds',
                        type=float, required=True)
    parser.add_argument('-y', '--delay', help='Delay before starting run',
                        type=int, required=False, default=0)
    parser.add_argument('-r', '--destination', help='Destination IPv4 address',
                        required=True)
    parser.add_argument('-sa', '--source-addr', help='Source address')
    parser.add_argument('-sp', '--source-port', type=int,
                        help='Source port else it will be random')
    parser.add_argument('-p', '--port', help='Destination port', type=int,
                        required=True)
    parser.add_argument('-m', '--msg', help='Message to send', required=True)
    parser.add_argument('-l', '--loglevel',
                        help='Log Level <DEBUG|INFO|WARNING|ERROR> defaults '
                             'to INFO',
                        required=False, default='INFO')
    parser.add_argument('-f', '--logfile',
                        help='File to log to defaults to console',
                        required=False, default=None)
    parser.add_argument('-z', '--interface',
                        help='Linux named ethernet device. Defaults to eth0',
                        required=False, default='eth0')
    parser.add_argument('-s', '--switch_ethernet',
                        help='Switch Ethernet Interface. Defaults to '
                             'ff:ff:ff:ff:ff:ff',
                        required=False, default='ff:ff:ff:ff:ff:ff')
    parser.add_argument('-t', '--tcp', dest='tcp', action='store_true',
                        required=False)
    args = parser.parse_args()
    return args


def device_send(args):
    numeric_level = getattr(logging, args.loglevel.upper(), None)
    basicConfig(format=FORMAT, level=numeric_level, filename=args.logfile)
    addr = socket.gethostbyname(args.destination)
    count = int((args.duration - args.delay) / args.interval)
    interface = get_if(args.interface)
    logger.info('Delaying %d seconds' % args.delay)
    sleep(args.delay)

    logger.info(
        'sending %s packets at %s sec/packet on interface %r to %s for %s '
        'seconds',
        count, args.interval, interface, args.destination,
        (args.duration - args.delay))
    logger.info('SRC ADDR for interface %s - %s', interface,
                get_if_hwaddr(interface))
    pkt = Ether(src=get_if_hwaddr(interface), dst=args.switch_ethernet)
    logger.info('packet Ether obj - %s', pkt)

    if args.source_addr:
        src_ip = args.source_addr
    else:
        src_ip = get_if_addr(interface)

    if args.source_port:
        src_port = args.source_port
    else:
        src_port = random.randint(49152, 65535)

    if args.tcp:
        pkt = pkt / IP(dst=addr, src=src_ip) / TCP(dport=args.port,
                                                   sport=src_port) / args.msg
    else:
        pkt = pkt / IP(dst=addr, src=src_ip) / UDP(dport=args.port,
                                                   sport=src_port) / args.msg

    pkt.show2()
    sendp(pkt, iface=interface, verbose=False, count=count,
          inter=args.interval)
    logger.info('Done')
    return


if __name__ == '__main__':
    logger.info('Starting Send')
    cmd_args = get_args()
    device_send(cmd_args)
