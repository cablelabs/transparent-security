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
import sys

import tofino.bfrt_grpc.client as bfrt_client
import logging

import grpc
from tofino.bfrt_grpc import bfruntime_pb2_grpc, bfruntime_pb2

from trans_sec.switch import GrpcRequestLogger, IterableQueue

logger = logging.getLogger('bfrt_connect')


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-g', '--grpc-addr', required=True,
                        help='The GRPC address')
    parser.add_argument('-n', '--switch-name', required=True,
                        help='The switch name')
    parser.add_argument('-p', '--proto-dump-file', required=False,
                        help='The GRPC logger')
    parser.add_argument('-c', '--client-id', required=False, default=0,
                        type=int, help='The client ID - default 0')
    parser.add_argument('-d', '--device-id', required=False, default=0,
                        type=int, help='The device ID - default 0')
    parser.add_argument('-m', '--is-master', required=False, type=bool,
                        default=False, help='Is master client')
    parser.add_argument('-t', '--table-name', required=False,
                        help='The table name for logging the ID')
    parser.add_argument('-ct', '--clear-tables', required=False, type=bool,
                        default=False,
                        help='The table name for logging the ID')

    parser.add_argument('-l', '--log-dir', type=str, required=False,
                        default=None)
    parser.add_argument('-lf', '--log-file', type=str, required=False,
                        default='insert_p4_table.log')
    return parser.parse_args()


def get_table_id(tbl_info, in_table_name):
    for table_name, table in tbl_info.table_dict.items():
        if table_name == in_table_name:
            logger.info('Table [%s] found with ID [%s]', table_name, table.info.id)
            return table.info.id


if __name__ == '__main__':
    """
    Inserts entries into P4 tables based on the entries within table config
    file
    """
    args = get_args()
    if args.log_dir and args.log_file:
        log_file = '{}/{}'.format(args.log_dir, args.log_file)
        logging.basicConfig(level=logging.DEBUG, filename=log_file)
    else:
        logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

    channel = grpc.insecure_channel(args.grpc_addr)
    if args.proto_dump_file:
        logger.info('Adding interceptor with file - [%s] to device [%s]',
                    args.proto_dump_file, args.grpc_addr)
        interceptor = GrpcRequestLogger(args.proto_dump_file)
        channel = grpc.intercept_channel(channel, interceptor)

    logger.info('Creating client stub to address - [%s]', args.grpc_addr)
    client_stub = bfruntime_pb2_grpc.BfRuntimeStub(channel)
    requests_stream = IterableQueue()
    stream_msg_resp = client_stub.StreamChannel(iter(requests_stream))

    logger.info('Creating client interface with client stub')
    logger.debug('grpc-addr - [%s], client_id - [%s], device_id - [%s], '
                 'is_master - [%s]',
                 args.grpc_addr, args.client_id, args.device_id,
                 args.is_master)
    interface = bfrt_client.ClientInterface(
        grpc_addr=args.grpc_addr, client_id=args.client_id,
        device_id=args.device_id, is_master=args.is_master)

    # interface.bind_pipeline_config(args.switch_name)
    # bfrt_info = interface.bind_pipeline_config(args.switch_name)
    logger.info('Retrieving bfrt_info for switch - [%s]', args.switch_name)
    bfrt_info = interface.bfrt_info_get(args.switch_name)
    logger.info('Table info - [%s]', bfrt_info)
    logger.info('Table info class - [%s]', bfrt_info.__class__)

    if args.clear_tables:
        logger.info('Clearing tables')
        interface.clear_all_tables()
        logger.info('Completed clearing tables')

    # Attempt to receive the ID for the args.table_name argument
    if args.table_name:
        table_info = get_table_id(bfrt_info, args.table_name)
        logger.info('table_info = %s', table_info)

        if not table_info:
            logger.info('Retrieve table name - [%s]', args.table_name)
            req = bfruntime_pb2.ReadRequest()
            req.client_id = args.client_id
            req.target.device_id = args.device_id

            # entity = req.entities.add()
            # logger.debug('entity = ', entity)
            object_id = req.entities.add().object_id
            object_id.table_object.table_name = args.table_name

            ex = None
            try:
                for rep in client_stub.Read(req):
                    logger.info('Table ID - [%s]', rep.entities[0].object_id.id)
            except Exception as e:
                ex = e
            finally:
                if ex:
                    logger.error("Exit with error - [%s]", ex)
                    raise ex
                else:
                    logger.info('Graceful exit')
                    exit(0)

    logger.info('Exit 0')
    exit()
