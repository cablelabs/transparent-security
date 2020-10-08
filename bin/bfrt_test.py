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

from __future__ import print_function

import logging
import os
import sys

import argparse
import bfrt_grpc.client as bfrt_client

SDE_INSTALL = os.environ['SDE_INSTALL']
SDE_PYTHON_27 = os.path.join(SDE_INSTALL, 'lib', 'python2.7', 'site-packages')

sys.path.append(SDE_PYTHON_27)
sys.path.append(os.path.join(SDE_PYTHON_27, 'tofino'))


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-g', '--grpc-addr', required=True,
                        help='The GRPC address in the form host:port')
    parser.add_argument('-i', '--ingress', required=True, type=str,
                        help='The name of the table to manipulate')
    parser.add_argument('-d', '--device_id', required=False, type=int,
                        default=0, help='The name of the table to manipulate')
    parser.add_argument('-t', '--table', required=False, type=str,
                        default='data_forward_t',
                        help='The name of the table to manipulate')
    parser.add_argument('-a', '--action', required=False, type=str,
                        default='data_forward',
                        help='The name of the table to manipulate')
    parser.add_argument('-f', '--mac-field', required=False, type=str,
                        default='hdr.ethernet.dst_mac',
                        help='The name of the table to manipulate')
    parser.add_argument('-m', '--mac', required=False, type=str,
                        default='00:00:00:01:01:01',
                        help='The key value to the data_forward_t table')
    parser.add_argument('-p', '--port', required=False, type=int,
                        default=2,
                        help='The acton value to the data_forward action')
    return parser.parse_args()


if __name__ == '__main__':
    """
    Inserts entries into P4 tables based on the entries within table config
    file
    """
    args = get_args()
    logger = logging.getLogger('bfrt_connect')
    logging.basicConfig(level=logging.DEBUG)
    #
    # Connect to the BF Runtime Server
    #
    interface = bfrt_client.ClientInterface(
        grpc_addr=args.grpc_addr,
        client_id=0,
        device_id=0,
        is_master=True)
    logger.info('Connected to BF Runtime Server')

    target = bfrt_client.Target(device_id=args.device_id, pipe_id=0xffff)
    #
    # Get the information about the running program
    #
    bfrt_info = interface.bfrt_info_get()
    p4_name = bfrt_info.p4_name_get()
    logger.info('The target runs program ', p4_name)
    interface.bind_pipeline_config(p4_name)

    table_name = "{}.{}".format(args.ingress, args.table)
    logger.info('Table name - [%s]', table_name)
    table = bfrt_info.table_get(table_name)
    logger.info('Table class - [%s]', table.__class__)
    table.info.key_field_annotation_add(args.mac_field, 'mac')

    action_name = "{}.{}".format(args.ingress, args.action)

    table.entry_add(target,
                    [bfrt_client.KeyTuple(args.mac_field, args.mac)],
                    [bfrt_client.DataTuple('port', val=args.port)])

    interface._tear_down_stream()
