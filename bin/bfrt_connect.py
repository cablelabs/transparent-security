#!/usr/bin/env python

# Copyright (c) 2020 Cable Television Laboratories, Inc.
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

import bfrt_grpc.client as bfrt_client
import grpc

from trans_sec.switch import GrpcRequestLogger


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-g', '--grpc-addr', required=False,
                        default='localhost:50052',
                        help='The GRPC address in the form host:port')
    parser.add_argument('-n', '--program-name', required=False,
                        default=None,
                        help='The P4 program name')
    parser.add_argument('-p', '--proto-dump-file', required=False,
                        help='The GRPC logger')
    parser.add_argument('-c', '--client-id', required=False, default=0,
                        type=int, help='The client ID - default 0')
    parser.add_argument('-d', '--device-id', required=False, default=0,
                        type=int, help='The device ID - default 0')
    parser.add_argument('-m', '--is-master', required=False, type=bool,
                        default=True, help='Is master client')
    parser.add_argument('-t', '--table-name', required=False,
                        help='The table name for logging the ID')
    parser.add_argument('-l', '--log-dir', type=str, required=False,
                        default=None)
    parser.add_argument('-lf', '--log-file', type=str, required=False,
                        default='insert_p4_table.log')
    parser.add_argument('-R', '--reset', '--clear', type=bool, required=False,
                        default=False,
                        help='Clear all tables before programming')
    return parser.parse_args()


if __name__ == '__main__':
    """
    Inserts entries into P4 tables based on the entries within table config
    file
    """
    args = get_args()
    logger = logging.getLogger('bfrt_connect')

    #
    # Set up Logging
    #
    if args.log_dir and args.log_file:
        log_file = '{}/{}'.format(args.log_dir, args.log_file)
        logging.basicConfig(level=logging.DEBUG, filename=log_file)
    else:
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    #
    # Connect to the BF Runtime Server
    #
    logger.info('Creating client interface with client stub')
    logger.debug('grpc-addr - [%s], client_id - [%s], device_id - [%s], '
                 'is_master - [%s]',
                 args.grpc_addr, args.client_id, args.device_id,
                 args.is_master)

    interface = bfrt_client.ClientInterface(
        grpc_addr=args.grpc_addr, client_id=args.client_id,
        device_id=args.device_id, is_master=args.is_master)

    #
    # Optional: Add GRPC Logging
    #
    if args.proto_dump_file:
        logger.info('Adding interceptor with file - [%s] to device [%s]',
                    args.proto_dump_file, args.grpc_addr)
        interceptor = GrpcRequestLogger(args.proto_dump_file)
        interface.channel = grpc.intercept_channel(interface.channel,
                                                   interceptor)

    #
    # Get the information about the running program
    #
    bfrt_info = interface.bfrt_info_get(args.program_name)

    # Attempt to receive the ID for the args.table_name argument
    if args.table_name:
        logger.info('Retrieve table name - [%s]', args.table_name)
        try:
            table = bfrt_info.table_get(args.table_name)
            logger.info('Table ID - [%s]', table.info.id_get())
        except Exception as e:
            logger.error("Exit with error - [%s]", e)

    #
    # A small workaround to close the connection properly. That should be
    # addressed in the future versions of SDE
    interface._tear_down_stream()

    #
    # The End
    #
    logger.info('Exit 0')
