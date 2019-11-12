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

from scapy.all import get_if_list, get_if_hwaddr
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp

# Logger stuff
filename = 'send_udp'
logger = getLogger(filename)
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
    parser.add_argument('-d', '--duration',
                        help='Number of seconds to run, 0 means forever',
                        type=int, required=True)
    parser.add_argument('-i', '--interval',
                        help='How often to send packets in seconds',
                        type=float, required=True)
    parser.add_argument('-y', '--delay', help='Delay before starting run',
                        type=int, required=False, default=0)
    parser.add_argument('-r', '--destination', help='Destination IPv4 address',
                        required=True)
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
    parser.add_argument('-e', '--src_mac', help='Src MAC Address',
                        required=False)
    args = parser.parse_args()
    return args


def device_send(args):
    numeric_level = getattr(logging, args.loglevel.upper(), None)
    basicConfig(format=FORMAT, level=numeric_level, filename=args.logfile)
    addr = socket.gethostbyname(args.destination)
    interface = get_if(args.interface)
    logger.info('Delaying %d seconds' % args.delay)
    sleep(args.delay)
    src = args.src_mac
    if not src:
        src = get_if_hwaddr(interface)

    if args.duration is 0:
        logger.info(
            'sending packets at %s sec/packet on interface %r to %s forever',
            args.interval, interface, args.destination)
        pkt = Ether(src=src, dst=args.switch_ethernet)
        pkt = pkt / IP(dst=addr) / UDP(dport=args.port,
                                       sport=random.randint(49152,
                                                            65535)) / args.msg
        pkt.show2()
        sendp(pkt, iface=interface, verbose=False, loop=1, inter=args.interval)
    else:
        count = int((args.duration - args.delay) / args.interval)
        logger.info(
            'sending %s packets at %s sec/packet on interface '
            '%r to %s for %s seconds',
            count, args.interval, interface, args.destination,
            (args.duration - args.delay))
        pkt = Ether(src=src, dst=args.switch_ethernet)
        pkt = pkt / IP(dst=addr) / UDP(dport=args.port,
                                       sport=random.randint(49152,
                                                            65535)) / args.msg
        pkt.show2()
        sendp(pkt, iface=interface, verbose=False, count=count,
              inter=args.interval)
        logger.info('Done')
        return


if __name__ == '__main__':
    logger.info('Starting Send')
    cmd_args = get_args()
    device_send(cmd_args)
