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
import sys

import yaml

from trans_sec.p4runtime_lib.bmv2 import Bmv2SwitchConnection
from trans_sec.p4runtime_lib.helper import P4InfoHelper

logger = logging.getLogger('insert_p4_table_entry')


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--grpc_addr', type=str, required=True,
                        help='Switch grpc host:port')
    parser.add_argument('-d', '--dev_id', type=int, required=False, default=0,
                        help='The device ID (default 0)')
    parser.add_argument(
        '-i', '--insert', type=str, required=False, default='True',
        help='When true insert record else delete (default "True")')
    parser.add_argument(
        '-p', '--p4-info-fpath', type=str, required=False, default=0,
        help='The file path of the switch associated p4info file')
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

    logger.info('Connecting to BMV2 Switch #[%s] at [%s] loaded with P4 [%s]',
                args.dev_id, args.grpc_addr, args.p4_info_fpath)
    p4info_helper = P4InfoHelper(args.p4_info_fpath)
    switch = Bmv2SwitchConnection(
        name='test', address=args.grpc_addr, device_id=args.dev_id)
    switch.master_arbitration_update()

    for entry_config in table_entry_config:
        logger.info('Entry config - [%s]', entry_config)
        logger.info('Writing table entry - [%s] for insert - [%s]',
                    entry_config, args.insert)

        if args.insert == 'True':
            table_entry = p4info_helper.build_table_entry(
                table_name=entry_config['table_name'],
                match_fields=entry_config.get('match_fields'),
                action_name=entry_config.get('action_name'),
                action_params=entry_config.get('action_params'),
            )
            logger.info('Inserting table entry')
            switch.write_table_entry(table_entry)
        else:
            table_entry = p4info_helper.build_table_entry(
                table_name=entry_config['table_name'],
                match_fields=entry_config.get('match_fields'),
            )
            logger.info('Deleting table entry')
            switch.delete_table_entry(table_entry)
