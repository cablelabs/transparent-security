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

import yaml

from trans_sec.p4runtime_lib.bmv2 import (GatewaySwitch, AggregateSwitch,
                                          CoreSwitch)
from trans_sec.p4runtime_lib.helper import P4InfoHelper

logger = logging.getLogger('insert_p4_table_entry')


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-s', '--switch-name', required=True,
                        help='The switch name to control')
    parser.add_argument('-t', '--topo', required=True,
                        help='The location to the topology file')
    parser.add_argument('-n', '--ingress', required=True,
                        help='The P4 ingress classname')
    parser.add_argument(
        '-i', '--insert', type=str, required=False, default='True',
        help='When true insert record else delete (default "True")')
    parser.add_argument('-tc', '--table-config',
                        help='Table insertion config file',
                        type=str, required=False)
    parser.add_argument('-l', '--log-dir', type=str, required=False,
                        default=None)
    parser.add_argument('-lf', '--log-file', type=str, required=False,
                        default='insert_p4_table.log')
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
    """
    Inserts entries into P4 tables based on the entries within table config
    file
    """
    args = get_args()
    if args.log_dir and args.log_file:
        log_file = '{}/{}'.format(args.log_dir, args.log_file)
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG,
                            filename=log_file)
    else:
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    table_entry_config = read_yaml_file(args.table_config)
    topo = read_yaml_file(args.topo)
    sw_info = topo['switches'][args.switch_name]

    logger.info('Connecting to BMV2 Switch #[%s]', sw_info)
    p4info_helper = P4InfoHelper(sw_info['runtime_p4info'])

    for entry_config in table_entry_config:
        logger.info('Entry config - [%s]', entry_config)
        logger.info('Writing table entry - [%s] for insert - [%s]',
                    entry_config, args.insert)

        switch = None
        if sw_info['type'] == 'gateway':
            switch = GatewaySwitch(p4info_helper, sw_info)
        elif sw_info['type'] == 'aggregate':
            switch = AggregateSwitch(p4info_helper, sw_info)
        elif sw_info['type'] == 'core':
            switch = CoreSwitch(p4info_helper, sw_info)

        if not switch:
            raise Exception('Switch type of [%s] is not supported',
                            sw_info['type'])
        switch.master_arbitration_update()

        match_fields = dict()
        if 'match_fields' in entry_config:
            logger.info('Match fields obj - [%s]',
                        entry_config['match_fields'])
            for key, value in entry_config['match_fields'].items():
                if isinstance(value, list):
                    logger.debug('Match fields list - [%s]', value)
                    match_fields[key] = (value[0], value[1])
                else:
                    logger.debug('Match fields list - [%s]', value)
                    match_fields[key] = value

        if args.insert == 'True':
            logger.info(
                'Entry configuration for table entry - [%s] and match fields '
                '- [%s]', entry_config, match_fields)
            table_entry = p4info_helper.build_table_entry(
                table_name=entry_config['table_name'],
                match_fields=match_fields,
                action_name=entry_config.get('action_name'),
                action_params=entry_config.get('action_params'),
            )
            logger.debug(
                'Writing table entry to table [%s], with action name - [%s], '
                'match fields - [%s], action_params - [%s]',
                entry_config['table_name'], entry_config.get('action_name'),
                match_fields, entry_config.get('action_params'))
            switch.write_table_entry(table_entry)
        else:
            table_entry = p4info_helper.build_table_entry(
                table_name=entry_config['table_name'],
                match_fields=entry_config.get('match_fields'),
            )
            logger.info('Deleting table entry')
            switch.delete_table_entry(table_entry)
