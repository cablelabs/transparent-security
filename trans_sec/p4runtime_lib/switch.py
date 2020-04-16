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
import logging
from Queue import Queue
from abc import abstractmethod
from datetime import datetime

import grpc
from p4.v1 import p4runtime_pb2, p4runtime_pb2_grpc

MSG_LOG_MAX_LEN = 1024

logger = logging.getLogger('switch')


class SwitchConnection(object):

    def __init__(self, name=None, address='127.0.0.1:50051', device_id=0,
                 proto_dump_file=None):
        self.name = name
        self.device_id = device_id
        channel = grpc.insecure_channel(address)
        if proto_dump_file is not None:
            logger.info('Adding interceptor with file - [%s]', proto_dump_file)
            interceptor = GrpcRequestLogger(proto_dump_file)
            channel = grpc.intercept_channel(channel, interceptor)

        logger.info('Creating client stub to channel - [%s] at address - [%s]',
                    channel, address)
        self.client_stub = p4runtime_pb2_grpc.P4RuntimeStub(channel)
        self.requests_stream = IterableQueue()
        self.stream_msg_resp = self.client_stub.StreamChannel(iter(
            self.requests_stream))
        self.proto_dump_file = proto_dump_file

    @abstractmethod
    def build_device_config(self, **kwargs):
        raise NotImplemented

    def shutdown(self):
        logger.info('Shutting down switch named - [%s]', self.name)
        self.requests_stream.close()
        self.stream_msg_resp.cancel()

    def master_arbitration_update(self):
        logger.info('Master arbitration update on switch - [%s]', self.name)
        request = p4runtime_pb2.StreamMessageRequest()
        request.arbitration.device_id = self.device_id
        request.arbitration.election_id.high = 0
        request.arbitration.election_id.low = 1
        self.requests_stream.put(request)

    def set_forwarding_pipeline_config(self, p4info, device_config):
        logger.info('Setting Forwarding Pipeline Config on switch - [%s] ',
                    self.name)
        logger.debug('P4Info - [%s] ', p4info)
        request = p4runtime_pb2.SetForwardingPipelineConfigRequest()
        request.election_id.low = 1
        request.device_id = self.device_id
        config = request.config

        config.p4info.CopyFrom(p4info)
        config.p4_device_config = device_config.SerializeToString()

        request.action = \
            p4runtime_pb2.SetForwardingPipelineConfigRequest.VERIFY_AND_COMMIT

        logger.info('Request for SetForwardingPipelineConfig to device - [%s]',
                    self.name)
        self.client_stub.SetForwardingPipelineConfig(request)
        logger.info('Completed SetForwardingPipelineConfig to device - [%s]',
                    request.device_id)

    def write_table_entry(self, table_entry):
        self.__write_to_table(table_entry, p4runtime_pb2.Update.INSERT)

    def delete_table_entry(self, table_entry):
        self.__write_to_table(table_entry, p4runtime_pb2.Update.DELETE)

    def __write_to_table(self, table_entry, type):
        logger.info('Writing table entry on switch [%s] - [%s]',
                    self.name, table_entry)
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = 1
        update = request.updates.add()
        update.type = type
        update.entity.table_entry.CopyFrom(table_entry)
        try:
            logger.debug('Request for writing table entry to device %s - [%s]',
                         self.device_id, request)
            self.client_stub.Write(request)
        except Exception as e:
            logging.error('Error writing table entry - [%s]', e)
            raise e

    def read_table_entries(self, table_id=None):
        logger.info('Reading table entry on switch [%s] with table ID - [%s]',
                    self.name, table_id)
        request = p4runtime_pb2.ReadRequest()
        request.device_id = self.device_id
        entity = request.entities.add()
        table_entry = entity.table_entry
        if table_id is not None:
            table_entry.table_id = table_id
        else:
            table_entry.table_id = 0

        logger.debug('Request for reading table entries to device %s - [%s]',
                     self.device_id, request.device_id)
        for response in self.client_stub.Read(request):
            logger.info('Table read response - [%s]', response)
            yield response

    def write_clone_entries(self, pre_entry):
        logger.info('Packet info for insertion to cloning table - %s',
                    pre_entry)
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = 1
        update = request.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        update.entity.packet_replication_engine_entry.CopyFrom(pre_entry)

        try:
            logger.debug(
                'Request for writing a clone request to device %s - [%s]',
                self.device_id, request)
            self.client_stub.Write(request)
        except Exception as e:
            logging.error('Error requesting [%s] clone - [%s]', request, e)
            raise e

    def delete_clone_entries(self, pre_entry):
        logger.info('Packet info for deleting the clone entry - %s',
                    pre_entry)
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = 1
        update = request.updates.add()
        update.type = p4runtime_pb2.Update.DELETE
        update.entity.packet_replication_engine_entry.CopyFrom(pre_entry)

        try:
            logger.debug(
                'Request for deleting a clone entry on the device %s - [%s]',
                self.device_id, request)
            self.client_stub.Write(request)
        except Exception as e:
            logging.error('Error requesting [%s] clone - [%s]', request, e)
            raise e

    def read_counters(self, counter_id=None, index=None):
        logger.info('Read counter with ID - [%s] and index - [%s]',
                    counter_id, index)
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

        logger.debug('Request for reading counters to device %s - [%s]',
                     self.device_id, request)
        for response in self.client_stub.Read(request):
            yield response

    def reset_counters(self, counter_id=None, index=None):
        logger.info('Reset counter with ID - [%s] and index - [%s]',
                    counter_id, index)
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

        logger.debug('Request for resetting counters to device %s - [%s]',
                     self.device_id, request)
        self.client_stub.Write(request)

    def write_digest_entry(self, digest_entry):
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = 1
        update = request.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        update.entity.digest_entry.CopyFrom(digest_entry)
        self.client_stub.Write(request)
        logger.info('Digest Entry written')

    def digest_list_ack(self, digest_ack):
        logger.debug("Before sending Digest List Acknowledgement")
        request = p4runtime_pb2.StreamMessageRequest()
        request.digest_ack.CopyFrom(digest_ack)
        self.requests_stream.put(request)
        logger.debug("After receiving Digest List Acknowledgement")

    def digest_list(self):
        logger.debug("Before receiving digest list")
        for item in self.stream_msg_resp:
            logger.debug("After receiving digest list, returning %s", item)
            return item

    def write_multicast_entry(self, mc_entry):
        request = p4runtime_pb2.WriteRequest()
        request.device_id = self.device_id
        request.election_id.low = 1
        update = request.updates.add()
        update.type = p4runtime_pb2.Update.INSERT
        update.entity.packet_replication_engine_entry.CopyFrom(mc_entry)

        try:
            logger.debug(
                'Request for writing a multicast entry to device %s - [%s]',
                self.device_id, request)
            self.client_stub.Write(request)
        except Exception as e:
            logging.error('Error requesting [%s] multicast - [%s]', request, e)
            raise e


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
