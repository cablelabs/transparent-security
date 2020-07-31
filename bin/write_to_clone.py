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

from trans_sec.p4runtime_lib.p4rt_switch import P4RuntimeSwitch
from trans_sec.p4runtime_lib.helper import P4InfoHelper
from trans_sec.switch import SwitchConnection

logger = logging.getLogger('insert_p4_clone_session_entry')


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--grpc_addr', type=str, required=True,
                        help='Switch grpc host:port')
    parser.add_argument('-d', '--dev_id', type=int, required=False, default=0,
                        help='The device ID (default 0)')
    parser.add_argument(
        '-p', '--p4-info-fpath', type=str, required=False, default=0,
        help='The file path of the switch associated p4info file')
    parser.add_argument('-l', '--log-dir', type=str, required=False,
                        default=None)
    parser.add_argument('-lf', '--log-file', type=str, required=False,
                        default='insert_p4_table.log')
    parser.add_argument('-c', '--clone', type=str, required=False,
                        default='True', help='Build clone entry')
    parser.add_argument('-ce', '--clone-egress', type=int, required=False,
                        default=0, help='Clone egress port')
    return parser.parse_args()


if __name__ == '__main__':
    """
    Inserts clone entries based on the table config file
    """
    args = get_args()
    if args.log_dir and args.log_file:
        log_file = '{}/{}'.format(args.log_dir, args.log_file)
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG,
                            filename=log_file)
    else:
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    logger.info('Connecting to BMV2 Switch #[%s] at [%s] loaded with P4 [%s]',
                args.dev_id, args.grpc_addr, args.p4_info_fpath)
    p4info_helper = P4InfoHelper(args.p4_info_fpath)

    # TODO/FIXME - This will break and need to know which type of switch
    #  connection to start
    switch = SwitchConnection(
        name='test', address=args.grpc_addr, device_id=args.dev_id)
    switch.master_arbitration_update()

    if args.clone == 'True':
        clone_entry = p4info_helper.build_clone_entry(args.clone_egress)
        logger.info('Inserting clone entry [%s]', clone_entry)
        switch.write_clone_entries(clone_entry)
    else:
        clone_entry = p4info_helper.build_clone_entry(args.clone_egress)
        logger.info('Deleting clone entry [%s]', clone_entry)
        switch.delete_clone_entries(clone_entry)
