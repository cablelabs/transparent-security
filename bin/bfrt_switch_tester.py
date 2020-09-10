#!/usr/bin/env python

# Copyright (c) 2020 Cable Television Laboratories, Inc.
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

import yaml

from trans_sec.bfruntime_lib.aggregate_switch import AggregateSwitch
from trans_sec.bfruntime_lib.core_switch import CoreSwitch
from trans_sec.bfruntime_lib.gateway_switch import GatewaySwitch


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--topo', required=True,
                        help='The location of the topology file')
    parser.add_argument('-n', '--program-name', required=False,
                        default=None,
                        help='The P4 program name')
    parser.add_argument('-p', '--proto-dump-file', required=False,
                        default=None, help='The GRPC logger')
    parser.add_argument('-c', '--client-id', required=False, default=0,
                        type=int, help='The client ID - default 0')
    parser.add_argument('-l', '--log-dir', type=str, required=False,
                        default=None)
    parser.add_argument('-lf', '--log-file', type=str, required=False,
                        default='insert_p4_table.log')
    return parser.parse_args()


if __name__ == '__main__':
    """
    Inserts entries into P4 tables based on the entries within table config
    file
    """
    args = get_args()
    #
    # Set up Logging
    #
    if args.log_dir and args.log_file:
        log_file = '{}/{}'.format(args.log_dir, args.log_file)
        logging.basicConfig(level=logging.DEBUG, filename=log_file)
    else:
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    logger = logging.getLogger('bfrt_switch_tester')

    topo_file = args.topo
    with open(topo_file, 'r') as f:
        if topo_file.endswith('json'):
            topo = json.load(f)
        else:
            topo = yaml.safe_load(f)

    logger.info('topo - [%s]', topo)

    for sw_info in topo['switches'].values():
        logger.info('sw_info - [%s]', sw_info)
        sw_type = sw_info['type']
        switch = None
        if sw_type == 'core':
            logger.info('Instantiating CoreSwitch')
            switch = CoreSwitch(sw_info)
        elif sw_type == 'aggregate':
            logger.info('Instantiating AggregateSwitch')
            switch = AggregateSwitch(sw_info)
        elif sw_type == 'gateway':
            logger.info('Instantiating GatewaySwitch')
            switch = GatewaySwitch(sw_info, args.proto_dump_file)

        logger.info('Adding switch ID to switch - [%s]', sw_info['id'])

        if switch:
            switch.add_switch_id(sw_info['id'])

            logger.info('Starting digest listeners')
            switch.start_digest_listeners()

            logger.info('Stopping switch')
            switch.stop_digest_listeners()

    #
    # The End
    #
    logger.info('Exit 0')
