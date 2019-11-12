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
import logging
import os
import sys
import yaml

from trans_sec.mininet.exercise import ExerciseRunner

logger = logging.getLogger('')


def __format_latency(l):
    """
    Helper method for parsing link latencies from the topology json.
    """
    if isinstance(l, (str, unicode)):
        return l
    else:
        return str(l) + "ms"


def get_args():
    cwd = os.getcwd()
    default_logs = os.path.join(cwd, 'logs')
    default_pcaps = os.path.join(cwd, 'pcaps')
    parser = argparse.ArgumentParser()
    parser.add_argument('-q', '--quiet', help='Suppress log messages.',
                        action='store_true', required=False, default=False)
    parser.add_argument('-t', '--topo', help='Path to topology json',
                        type=str, required=False,
                        default='./conf/topology_proposed.json')
    parser.add_argument('-l', '--log-dir', type=str, required=False,
                        default=default_logs)
    parser.add_argument('-lf', '--log-file', type=str, required=False,
                        default='run_p4_mininet.log')
    parser.add_argument('-p', '--pcap-dir', type=str, required=False,
                        default=default_pcaps)
    parser.add_argument('-j', '--switch_json', type=str, required=False)
    parser.add_argument('-b', '--behavioral-exe',
                        help='Path to behavioral executable',
                        type=str, required=False, default='simple_switch')
    parser.add_argument('-d', '--daemon', help='Run device daemon on hosts.',
                        type=bool, required=False, default=False)
    parser.add_argument('-dc', '--devices-config', help='Devices config',
                        type=str, required=True)
    parser.add_argument('-u', '--dashboard-url', help='Devices config.',
                        type=str, required=False, default=None)
    return parser.parse_args()


def read_yaml_file(config_file_path):
    """
    Reads a yaml file and returns a dict representation of it
    :return: a dict of the yaml file
    """
    logger.debug('Attempting to load configuration file - ' + config_file_path)
    config_file = None
    try:
        with open(config_file_path, 'r') as config_file:
            config = yaml.safe_load(config_file)
            logger.info('Loaded configuration')
        return config
    finally:
        if config_file:
            logger.info('Closing configuration file')
            config_file.close()


if __name__ == '__main__':
    args = get_args()
    log_file = '{}/{}'.format(args.log_dir, args.log_file)
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG,
                        filename=log_file)

    exercise = ExerciseRunner(
        args.topo, args.log_dir, args.pcap_dir, args.switch_json,
        read_yaml_file(args.devices_config), args.dashboard_url,
        args.behavioral_exe, args.quiet, args.daemon)
    exercise.run_exercise()
