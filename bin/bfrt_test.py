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

import codecs
import logging
import os
import sys

import argparse
import bfrt_grpc.client as bfrt_client

SDE_INSTALL   = os.environ['SDE_INSTALL']
SDE_PYTHON_27 = os.path.join(SDE_INSTALL, 'lib', 'python2.7', 'site-packages')

sys.path.append(SDE_PYTHON_27)
sys.path.append(os.path.join(SDE_PYTHON_27, 'tofino'))


def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-g', '--grpc-addr', required=True,
                        help='The GRPC address in the form host:port')
    parser.add_argument('-m', '--mac', required=False, type=str,
                        default='00:00:00:01:01:01',
                        help='The key value to the data_forward_t table')
    parser.add_argument('-p', '--port', required=False, type=int,
                        default=1,
                        help='The acton value to the data_forward action')
    return parser.parse_args()


if __name__ == '__main__':
    """
    Inserts entries into P4 tables based on the entries within table config
    file
    """
    args = get_args()
    logger = logging.getLogger('bfrt_connect')
    #
    # Connect to the BF Runtime Server
    #
    interface = bfrt_client.ClientInterface(
        grpc_addr=args.grpc_addr,
        client_id=0,
        device_id=0,
        is_master=True)
    print('Connected to BF Runtime Server')

    #
    # Get the information about the running program
    #
    bfrt_info = interface.bfrt_info_get()
    print('The target runs program ', bfrt_info.p4_name_get())
    interface.bind_pipeline_config(bfrt_info.p4_name_get())

    data_forward_t = bfrt_info.table_get('pipe.TpsAggIngress.data_forward_t')
    # kt = bfrt_client.KeyTuple('hdr.ethernet.dst_mac', value=args.mac)
    # data_forward_t.info.key_field_annotation_add("hdr.ethernet.dst_mac", "mac")
    # key = data_forward_t.make_key([kt])
    #
    # dt = bfrt_client.DataTuple('port', args.port)
    # # dt = bfrt_client.DataTuple(name='port', val=10)
    # data = data_forward_t.make_data([dt], 'TpsAggIngress.data_forward')
    # target = bfrt_client.Target(device_id=0, pipe_id=0xffff)
    # data_forward_t.entry_add(target, [key], [data])

    hex_decoder = codecs.getdecoder('hex_codec')
    encoded_mac = hex_decoder(args.mac.replace(':', ''))[0]
    logger.debug('encoded_mac - [%s]', encoded_mac)

    data_forward_t.entry_add('TpsAggIngress.data_forward_t',
                             'TpsAggIngress.data_forward',
                             [bfrt_client.KeyTuple('hdr.ethernet.dst_mac',
                                                   bytearray(encoded_mac))],
                             [bfrt_client.DataTuple('port', val=args.port)])

    # add_switch_id_t = bfrt_info.table_get('pipe.TpsAggIngress.add_switch_id_t')
    # kt = bfrt_client.KeyTuple('hdr.udp.dst_port', value=777)
    # key = add_switch_id_t.make_key([kt])
    #
    # dt = bfrt_client.DataTuple('switch_id', val=10)
    # data = add_switch_id_t.make_data([dt], 'TpsAggIngress.add_switch_id')
    # target = bfrt_client.Target(device_id=0, pipe_id=0xffff)
    #
    # add_switch_id_t.entry_add(target, [key], [data])

    interface._tear_down_stream()
