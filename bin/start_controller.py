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
from trans_sec.controller.gateway_controller import GatewayController

logger = logging.getLogger('')


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-l', '--log-dir', type=str, required=True,
                        default=None)
    parser.add_argument('-t', '--type', type=str, required=True,
                        choices=['gateway', 'aggregate', 'core'])
    parser.add_argument('-f', '--topo-file', type=str, required=True)
    return parser.parse_args()


def read_yaml_file(yaml_file):
    """
    Reads a yaml file and returns a dict representation of it
    :return: a dict of the yaml file
    """
    logger.debug('Attempting to load configuration file - ' + yaml_file)
    config_file = None
    try:
        with open(yaml_file, 'r') as config_file:
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
        topo = read_yaml_file(args.topo_file)

    controller = None
    if args.type == 'gateway':
        controller = GatewayController()
    else:
        raise NotImplemented
