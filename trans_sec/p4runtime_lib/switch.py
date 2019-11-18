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
#
# Originally copied from:
#
# Copyright 2017-present Open Networking Foundation
#
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
#
# noinspection PyCompatibility
from Queue import Queue
from abc import abstractmethod
from datetime import datetime

import grpc
import logging
from p4.tmp import p4config_pb2
from p4.v1 import p4runtime_pb2, p4runtime_pb2_grpc

MSG_LOG_MAX_LEN = 1024

# List of all active connections
connections = []

logger = logging.getLogger('switch')


def shutdown_all_switch_connections():
    for c in connections:
        c.shutdown()


class SwitchConnection(object):

    def __init__(self, name=None, address='127.0.0.1:50051', device_id=0,
                 proto_dump_file=None):
        self.name = name
        self.address = address
        self.device_id = device_id
        self.p4info = None
        self.channel = grpc.insecure_channel(self.address)
        if proto_dump_file is not None:
            interceptor = GrpcRequestLogger(proto_dump_file)
            self.channel = grpc.intercept_channel(self.channel, interceptor)
        self.client_stub = p4runtime_pb2_grpc.P4RuntimeStub(self.channel)
        self.requests_stream = IterableQueue()
        self.stream_msg_resp = self.client_stub.StreamChannel(iter(
            self.requests_stream))
        self.proto_dump_file = proto_dump_file
        connections.append(self)

    @abstractmethod
    def build_device_config(self, **kwargs):
        return p4config_pb2.P4DeviceConfig()

    def shutdown(self):
        self.requests_stream.close()
        self.stream_msg_resp.cancel()

    def master_arbitration_update(self):
        request = p4runtime_pb2.StreamMessageRequest()
        request.arbitration.device_id = self.device_id
        request.arbitration.election_id.high = 0
        request.arbitration.election_id.low = 1
        self.requests_stream.put(request)

    def set_forwarding_pipeline_config(self, p4info, **kwargs):
        device_config = self.build_device_config(**kwargs)
        request = p4runtime_pb2.SetForwardingPipelineConfigRequest()
        request.election_id.low = 1
        request.device_id = self.device_id
        config = request.config

        config.p4info.CopyFrom(p4info)
        config.p4_device_config = device_config.SerializeToString()

        request.action = \
            p4runtime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_COMMIT

        logger.info('Request for SetForwardingPipelineConfig to device - [%s]',
                    request.device_id)
        self.client_stub.SetForwardingPipelineConfig(request)
        logger.info('Completed SetForwardingPipelineConfig to device - [%s]',
                    request.device_id)

    def write_table_entry(self, table_entry):
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = 1
        update = request.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        update.entity.table_entry.CopyFrom(table_entry)

        logger.info('Request for writing table entry to device - [%s]',
                    request.device_id)
        self.client_stub.Write(request)

    def read_table_entries(self, table_id=None):
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity = request.entities.add()
        table_entry = entity.table_entry
        if table_id is not None:
            table_entry.table_id = table_id
        else:
            table_entry.table_id = 0

        logger.info('Request for reading table entries to device - [%s]',
                    request.device_id)
        for response in self.client_stub.Read(request):
            yield response

    def write_clone_entries(self, packet_replication_engine_entry):
        logger.info('Packet info for insertion to cloning table - %s',
                    packet_replication_engine_entry)
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = 1
        update = request.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        update.entity.packet_replication_engine_entry.CopyFrom(
            packet_replication_engine_entry)

        try:
            logger.info('Request for writing a clone request to device - [%s]',
                        request.device_id)
            self.client_stub.Write(request)
        except Exception as e:
            logging.error('Error requesting [%s] clone - [%s]', request, e)
            raise e

    def read_counters(self, counter_id=None, index=None):
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity = request.entities.add()
        counter_entry = entity.counter_entry
        if counter_id is not None:
            counter_entry.counter_id = counter_id
        else:
            counter_entry.counter_id = 0
        if index is not None:
            counter_entry.index.index = index

        logger.info('Request for reading counters to device - [%s]',
                    request.device_id)
        for response in self.client_stub.Read(request):
            yield response

    def reset_counters(self, counter_id=None, index=None):
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = 1
        update = request.updates.add()
        update.type = p4runtime_pb2.Update.MODIFY
        counter_entry = p4runtime_pb2.CounterEntry()
        if counter_id is not None:
            counter_entry.counter_id = counter_id
        else:
            counter_entry.counter_id = 0
        if index is not None:
            counter_entry.index.index = index
        counter_entry.data.byte_count = 0
        counter_entry.data.packet_count = 0
        update.entity.counter_entry.CopyFrom(counter_entry)

        logger.info('Request for resetting counters to device - [%s]',
                    request.device_id)
        self.client_stub.Write(request)


class GrpcRequestLogger(grpc.UnaryUnaryClientInterceptor,
                        grpc.UnaryStreamClientInterceptor):
    """Implementation of a gRPC interceptor that logs request to a file"""

    def __init__(self, log_file):
        self.log_file = log_file
        with open(self.log_file, 'w') as f:
            # Clear content if it exists.
            f.write("")

    def log_message(self, method_name, body):
        with open(self.log_file, 'a') as f:
            ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            msg = str(body)
            f.write("\n[%s] %s\n---\n" % (ts, method_name))
            if len(msg) < MSG_LOG_MAX_LEN:
                f.write(str(body))
            else:
                f.write(
                    "Message too long (%d bytes)! Skipping log...\n" % len(
                        msg))
            f.write('---\n')

    def intercept_unary_unary(self, continuation, client_call_details,
                              request):
        self.log_message(client_call_details.method, request)
        return continuation(client_call_details, request)

    def intercept_unary_stream(self, continuation, client_call_details,
                               request):
        self.log_message(client_call_details.method, request)
        return continuation(client_call_details, request)


class IterableQueue(Queue):
    _sentinel = object()

    def __iter__(self):
        return iter(self.get, self._sentinel)

    def close(self):
        self.put(self._sentinel)
