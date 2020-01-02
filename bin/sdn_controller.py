#!/usr/bin/env python2

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
import os

import pydevd
import yaml

from trans_sec.controller.ddos_sdn_controller import DdosSdnController

FORMAT = '%(levelname)s %(asctime)-15s %(filename)s %(message)s'
logger = logging.getLogger('sdn_controller')


def get_args():
    default_logs = os.path.join(os.getcwd(), 'logs')
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-l', '--loglevel',
        help='Log Level <DEBUG|INFO|WARNING|ERROR> defaults to INFO',
        required=False, default='INFO')

    parser.add_argument('-f', '--logfile',
                        help='File to log to defaults to console',
                        required=False, default=None)
    parser.add_argument('-ld', '--log-dir', type=str, required=False,
                        default=default_logs)
    parser.add_argument('-t', '--topo', help='Path to topology json',
                        required=False,
                        default='../mininet-start/conf/topology_proposed.json')
    parser.add_argument('-p', '--platform', help='Switch Platform',
                        required=True, type=str, choices=['bmv2', 'tofino'])
    parser.add_argument('-sc', '--scenario', help='Path to topology json',
                        required=False, default='scenario2')
    parser.add_argument('-s', '--switch-config-dir', dest='switch_config_dir',
                        help='Direction with Switch configurations',
                        required=True)
    parser.add_argument('-dh', '--debug-host', dest='debug_host',
                        help='remote debugging host IP')
    parser.add_argument('-dp', '--debug-port', dest='debug_port', default=5678,
                        help='the remote debugging port')
    parser.add_argument('-hsp', '--http-server-port', dest='http_server_port',
                        type=int, default=9998,
                        help='the http server port defaults to 9998')
    parser.add_argument('-lp', '--load-p4', type=str, required=True,
                        choices=['True', 'False'],
                        help='When set, the controller will not attempt to '
                             'load the P4 program onto the switches')
    return parser.parse_args()


def main():
    args = get_args()

    # Setup remote debugging
    if args.debug_host:
        pydevd.settrace(host=args.debug_host, port=int(args.debug_port),
                        stdoutToServer=True, stderrToServer=True)
    numeric_level = getattr(logging, args.loglevel.upper(), None)
    logging.basicConfig(format=FORMAT, level=numeric_level,
                        filename=args.logfile)

    topo_file = args.topo
    with open(topo_file, 'r') as f:
        if topo_file.endswith('json'):
            topo = json.load(f)
        else:
            topo = yaml.safe_load(f)

    logger.info(
        'Starting SDN Controller with topology - [%s] and load_p4 flag - [%s]',
        topo, eval(args.load_p4))
    sdn_controller = DdosSdnController(
        topo, args.platform, args.switch_config_dir, args.http_server_port,
        args.scenario, args.log_dir, eval(args.load_p4))
    sdn_controller.start()


if __name__ == '__main__':
    main()
