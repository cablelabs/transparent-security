#!/usr/bin/env python3

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
import yaml

from trans_sec.analytics.oinc import Oinc, SimpleAE, LoggerAE, IntLoggerAE
from trans_sec.utils.http_session import HttpSession

logger = logging.getLogger('start_ae')
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
    parser.add_argument('-c', '--conf-file', help='Tells AE how to startup',
                        required=True, dest='conf_file')
    parser.add_argument('-dh', '--debug-host', dest='debug_host',
                        help='remote debugging host IP')
    parser.add_argument('-dp', '--debug-port', dest='debug_port', default=5678,
                        help='the remote debugging port')
    return parser.parse_args()


def main():
    args = get_args()
    with open(args.conf_file, 'r') as conf_file:
        conf_dict = yaml.safe_load(conf_file)

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

    sdn_url = conf_dict['sdn_url']
    ae_type = conf_dict.get('service_type', 'SIMPLE')
    attack_ctx = conf_dict.get('sdn_attack_ctx', 'aggAttack')

    logger.info('Starting [%s] with SDN Controller url [%s] to [%s]',
                ae_type, sdn_url, attack_ctx)
    http_session = HttpSession(sdn_url)

    ae = None
    if ae_type == 'SIMPLE':
        logger.info('SimpleAE instantiated')
        logger.debug('SDN Context - [%s]', attack_ctx)
        ae = SimpleAE(http_session,
                      packet_count=int(conf_dict['packet_count']),
                      sample_interval=int(conf_dict['sample_interval']),
                      sdn_attack_context=attack_ctx,
                      drop_count=conf_dict.get('drop_count'))
    elif ae_type == 'OINC':
        logger.info('Oinc instantiated')
        ae = Oinc(http_session)
    elif ae_type == 'LOGGING':
        logger.info('LoggerAE instantiated')
        ae = LoggerAE(http_session)
    elif ae_type == 'INT':
        logger.info('LoggerAE instantiated')
        ae = IntLoggerAE(http_session)

    mon_intf = conf_dict['monitor_intf']
    drop_intf = conf_dict.get('drop_rpt_intf')
    logger.info('Begin sniffing for INT on [%s] and Drop Reports on [%s]',
                mon_intf, drop_intf)
    ae.start_sniffing(mon_intf, drop_intf)
    sys.stdout.flush()


if __name__ == '__main__':
    main()
