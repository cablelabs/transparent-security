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
import sys

from scapy.all import sniff

filename = 'receive_udp'
logger = logging.getLogger(filename)
FORMAT = '%(levelname)s %(asctime)-15s %(filename)s %(message)s'


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-i', '--iface', help='The network interface on which to sniff',
        required=True, dest='iface')
    parser.add_argument(
        '-p', '--proto-id', help='The proto_id to bind to', required=False,
        default=0x800, type=int, dest='proto_id')
    parser.add_argument(
        '-e', '--ether-type', help='The ether type to find to',
        required=False, default=0x212, type=int, dest='ether_type')
    parser.add_argument(
        '-f', '--logfile', help='File to log to defaults to console',
        required=True, dest='logfile')
    parser.add_argument(
        '-l', '--loglevel',
        help='Log Level <DEBUG|INFO|WARNING|ERROR> defaults to INFO',
        required=False, default='INFO', dest='loglevel')
    return parser.parse_args()


def log_packet(packet):
    logger.info('Packet data - [%s]', packet.summary())


def device_sniff(args):
    numeric_level = getattr(logging, args.loglevel.upper(), None)
    logging.basicConfig(format=FORMAT, level=numeric_level,
                        filename=args.logfile)
    logger.info("Sniffing for packets on iface - [%s]", args.iface)
    sys.stdout.flush()
    sniff(iface=args.iface, prn=lambda packet: log_packet(packet))


if __name__ == '__main__':
    cmd_args = get_args()
    device_sniff(cmd_args)
