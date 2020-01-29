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
import sys
import yaml

from trans_sec.controller import simple_controller

logger = logging.getLogger('')


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--log-dir', type=str, required=True,
                        default=None)
    parser.add_argument('-lf', '--log-file', type=str, required=False,
                        default='run_p4_mininet.log')
    parser.add_argument('-tc', '--table-config',
                        help='Table insertion config file',
                        type=str, required=False)
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

    topo_file = args.topo
    if topo_file.endswith('json'):
        with open(topo_file, 'r') as f:
            topo = json.load(f)
    else:
        topo = read_yaml_file(args.table_config)

    for entry in topo:
        simple_controller.insert_table_entry(entry)

    logger.info('Exercise Runner running indefinitely')
    while True:
        pass
