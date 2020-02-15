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

import p4runtime_sh.shell as sh

logger = logging.getLogger('clear_p4_table')


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--grpc_addr', type=str, required=True,
                        help='Switch grpc host:port')
    parser.add_argument('-d', '--dev_id', type=int, required=False, default=0,
                        help='The device ID (default 0)')
    parser.add_argument('-n', '--table-name', help='The table name to clean',
                        type=str, required=True)
    return parser.parse_args()


if __name__ == '__main__':
    """
    Clears all entries from a P4 table
    """
    args = get_args()
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    logger.info('Connecting to switch at [%s]', args.grpc_addr)
    sh.setup(device_id=args.dev_id, grpc_addr=args.grpc_addr)

    logger.info('Retrieving table entry - [%s]', args.table_name)
    table_entry = sh.TableEntry(args.table_name)
    logger.info('Table entry to clear - [%s]', table_entry)
    table_entry.read(lambda te: logger.info('Deleting - [%s]', te))
    table_entry.read(lambda te: te.delete())
    logger.info('Table [%s] cleared', args.table_name)

    sh.teardown()
