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

import pydevd

from trans_sec.analytics.oinc import Oinc, SimpleAE, LoggerAE, IntLoggerAE
from trans_sec.utils.http_session import HttpSession

logger = logging.getLogger('oinc')
FORMAT = '%(levelname)s %(asctime)-15s %(filename)s %(lineno)d %(message)s'


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-l', '--loglevel',
        help='Log Level <DEBUG|INFO|WARNING|ERROR> defaults to INFO',
        required=False, default='INFO')
    parser.add_argument('-f', '--logfile',
                        help='File to log to defaults to console',
                        required=False, default=None)
    parser.add_argument('-i', '--interface',
                        help='Linux interface to listen on', required=True)
    parser.add_argument('-dh', '--debug-host', dest='debug_host',
                        help='remote debugging host IP')
    parser.add_argument('-dp', '--debug-port', dest='debug_port', default=5678,
                        help='the remote debugging port')
    parser.add_argument('-s', '--sdn-url', dest='sdn_url', required=True,
                        help='the URL to the SDN controller')
    parser.add_argument('-t', '--type', dest='type', required=True,
                        choices=['OINC', 'SIMPLE', 'LOGGING', 'INT'],
                        help='Acceptable values OINC|SIMPLE|LOGGING|INT')
    return parser.parse_args()


def main():
    args = get_args()

    # Initialize logger
    numeric_level = getattr(logging, args.loglevel.upper(), None)

    if args.logfile:
        logging.basicConfig(format=FORMAT, level=numeric_level,
                            filename=args.logfile)
    else:
        logging.basicConfig(format=FORMAT, level=numeric_level)

    # Setup remote debugging
    if args.debug_host:
        pydevd.settrace(host=args.debug_host, port=int(args.debug_port),
                        stdoutToServer=True, stderrToServer=True,
                        suspend=False)
    logger.info('Starting Oinc with SDN Controller url [%s]', args.sdn_url)

    ae = None

    logger.info('Retrieving http session from url - [%s]', args.sdn_url)
    http_session = HttpSession(args.sdn_url)

    logger.info('Type of AE to instantiate - [%s]', args.type)
    if args.type == 'SIMPLE':
        logger.info('SimpleAE instantiated')
        ae = SimpleAE(http_session)
    elif args.type == 'OINC':
        logger.info('Oinc instantiated')
        ae = Oinc(http_session)
    elif args.type == 'LOGGING':
        logger.info('LoggerAE instantiated')
        ae = LoggerAE(http_session)
    elif args.type == 'INT':
        logger.info('LoggerAE instantiated')
        ae = IntLoggerAE(http_session)

    ae.start_sniffing(args.interface)
    sys.stdout.flush()


if __name__ == '__main__':
    main()
