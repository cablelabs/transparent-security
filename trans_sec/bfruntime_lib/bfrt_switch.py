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

import logging
import struct
from abc import ABC
from threading import Thread

import grpc
from tofino.bfrt_grpc import bfruntime_pb2_grpc

from trans_sec.switch import SwitchConnection, GrpcRequestLogger, IterableQueue

MSG_LOG_MAX_LEN = 1024

logger = logging.getLogger('switch')


class BFRuntimeSwitch(SwitchConnection, ABC):

    def __init__(self, p4info_helper, sw_info, p4_ingress, p4_egress,
                 proto_dump_file=None):
        super(BFRuntimeSwitch, self).__init__()
        channel = grpc.insecure_channel(self.grpc_addr)
        if proto_dump_file is not None:
            logger.info('Adding interceptor with file - [%s] to device [%s]',
                        proto_dump_file, self.grpc_addr)
            interceptor = GrpcRequestLogger(proto_dump_file)
            channel = grpc.intercept_channel(channel, interceptor)

        logger.info('Creating client stub to channel - [%s] at address - [%s]',
                    channel, self.grpc_addr)
        self.client_stub = bfruntime_pb2_grpc.BfRuntimeStub(channel)
        self.requests_stream = IterableQueue()
        self.stream_msg_resp = self.client_stub.StreamChannel(iter(
            self.requests_stream))
        self.proto_dump_file = proto_dump_file

        self.digest_thread = Thread(target=self.receive_digests)

    def start_digest_listeners(self):
        logger.info('Tofino currently not supporting digests')
        pass

    def stop_digest_listeners(self):
        logger.info('Tofino currently not supporting digests')
        pass

    def get_table_entry(self, table_name, action_name, match_fields,
                        action_params, ingress_class=True):
        raise NotImplementedError

    def add_data_forward(self, source_mac, ingress_port):
        raise NotImplementedError

    def build_device_config(self):
        """
        Builds the device config for Tofino
        """
        raise NotImplementedError

    def master_arbitration_update(self):
        raise NotImplementedError

    def set_forwarding_pipeline_config(self, device_config):
        raise NotImplementedError

    def write_table_entry(self, **kwargs):
        raise NotImplementedError

    def delete_table_entry(self, **kwargs):
        raise NotImplementedError

    def get_data_forward_macs(self):
        raise NotImplementedError

    def get_data_inspection_src_mac_keys(self):
        raise NotImplementedError

    def get_match_values(self, table_name):
        raise NotImplementedError

    def get_table_entries(self, table_name):
        raise NotImplementedError

    def read_table_entries(self, table_id=None):
        raise NotImplementedError

    def write_clone_entries(self, pre_entry):
        raise NotImplementedError

    def delete_clone_entries(self, pre_entry):
        raise NotImplementedError

    def read_counters(self, counter_id=None, index=None):
        raise NotImplementedError

    def reset_counters(self, counter_id=None, index=None):
        raise NotImplementedError

    def write_digest_entry(self, digest_entry):
        raise NotImplementedError

    def digest_list_ack(self, digest_ack):
        raise NotImplementedError

    def digest_list(self):
        raise NotImplementedError

    # def write_multicast_entry(self, hosts):
    #     raise NotImplementedError

    def write_arp_flood(self):
        raise NotImplementedError
