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
import json
import logging

import pydevd
import requests

logger = logging.getLogger('oinc')
FORMAT = '%(levelname)s %(asctime)-15s %(filename)s %(lineno)d %(message)s'


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-l', '--loglevel',
        help='Log Level <DEBUG|INFO|WARNING|ERROR> defaults to INFO',
        required=False, default='INFO')
    parser.add_argument(
        '-s', '--sdn-url', dest='sdn_url', required=False,
        default='localhost:9998', help='the URL to the SDN controller')
    parser.add_argument(
        '-o', '--operation', dest='operation', required=False,
        help='the operation to call', default='attack')
    parser.add_argument(
        '-p', '--protocol', dest='protocol', required=False,
        help='the protocol to call', default='http')

    parser.add_argument(
        '-dh', '--debug-host', dest='debug_host',
        help='remote debugging host IP')
    parser.add_argument(
        '-dp', '--debug-port', dest='debug_port', default=5678,
        help='the remote debugging port')

    attack = {
        'src_mac': '00:00:00:00:03:01',
        'src_ip': '192.168.3.2',
        'dst_ip': '10.2.5.2',
        'dst_port': '4323',
        'packet_size': '86',
        'attack_type': 'UDP Flood',
    }
    parser.add_argument('-a', '--rest-args', dest='rest_args', required=False,
                        default=attack, type=json.loads,
                        help='the REST call dict arguments')
    return parser.parse_args()


def main():
    args = get_args()

    # Initialize logger
    numeric_level = getattr(logging, args.loglevel.upper(), None)
    logging.basicConfig(format=FORMAT, level=numeric_level)

    # Setup remote debugging
    if args.debug_host:
        pydevd.settrace(host=args.debug_host, port=int(args.debug_port),
                        stdoutToServer=True, stderrToServer=True,
                        suspend=False)
    logger.info('Starting Oinc with SDN Controller url [%s]', args.sdn_url)

    logger.info('Retrieving http session from url - [%s]', args.sdn_url)
    url = '{}://{}/{}'.format(args.protocol, args.sdn_url, args.operation)
    ret_val = requests.post(url=url, params=args.rest_args)
    logger.info('Return value of REST call [%s]', ret_val)


if __name__ == '__main__':
    main()
