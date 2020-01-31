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
from scapy.layers.inet import IP

from trans_sec.analytics import oinc

logger = logging.getLogger('receive_packets')
FORMAT = '%(levelname)s %(asctime)-15s %(filename)s %(message)s'


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-i', '--iface', help='The network interface on which to sniff',
        required=True, dest='iface')
    parser.add_argument(
        '-f', '--logfile', help='File to log to defaults to console',
        required=False, dest='logfile')
    parser.add_argument(
        '-d', '--duration', default=0, dest='duration', type=int,
        help='Number of seconds to sniff - 0 is indefinite')
    parser.add_argument(
        '-l', '--loglevel',
        help='Log Level <DEBUG|INFO|WARNING|ERROR> defaults to INFO',
        required=False, default='INFO', dest='loglevel')
    return parser.parse_args()


def __log_packet(packet):
    if packet[IP].proto == 0xfd:
        logger.debug('INT Packet received')
        logger.warn('INT Packet data - [%s]', oinc.extract_int_data(packet))
    else:
        logger.debug('Non INT Packet received')
        logger.warn('Packet data - [%s]', packet.summary())


def device_sniff(iface, duration, log_file, log_level):
    numeric_level = getattr(logging, log_level, None)

    if log_file:
        logging.basicConfig(format=FORMAT, level=numeric_level,
                            filename=log_file)
    else:
        logging.basicConfig(format=FORMAT, level=numeric_level)

    logger.info("Sniffing for packets on iface - [%s]", iface)
    sys.stdout.flush()

    if duration > 0:
        logger.info('Running sniffer for [%s] seconds', duration)
        sniff(iface=iface, prn=lambda packet: __log_packet(packet),
              timeout=duration)
    else:
        logger.info('Running sniffer indefinitely')
        sniff(iface=iface, prn=lambda packet: __log_packet(packet))


if __name__ == '__main__':
    cmd_args = get_args()
    device_sniff(cmd_args.iface, cmd_args.duration,
                 cmd_args.logfile, cmd_args.loglevel.upper())
