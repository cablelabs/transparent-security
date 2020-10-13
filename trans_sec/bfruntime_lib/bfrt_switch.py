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
from abc import ABC

import grpc
import tofino.bfrt_grpc.client as bfrt_client
from google.rpc import code_pb2, status_pb2
from tofino.bfrt_grpc import bfruntime_pb2

from trans_sec.switch import SwitchConnection

MSG_LOG_MAX_LEN = 1024

logger = logging.getLogger('switch')


class BFRuntimeSwitch(SwitchConnection, ABC):
    def __init__(self, sw_info, client_id=0, is_master=True):
        super(BFRuntimeSwitch, self).__init__(sw_info)

        logger.info('Connecting to the BFRT server @ [%s], client_id [%s],'
                    ' device_id [%s]',
                    self.grpc_addr, client_id, self.device_id)
        self.interface = bfrt_client.ClientInterface(
            grpc_addr=self.grpc_addr, client_id=client_id,
            device_id=self.device_id, is_master=is_master)
        self.target = bfrt_client.Target(
            device_id=self.device_id, pipe_id=0xffff)

        if self.sw_info.get('arch') and self.sw_info['arch'] != 'v1model':
            self.prog_name = "{}_{}".format(self.name, self.sw_info['arch'])
        else:
            self.prog_name = "{}}".format(self.name, self.sw_info['arch'])

        self.bfrt_info = self.interface.bfrt_info_get(self.prog_name)

        p4_name = self.bfrt_info.p4_name_get()
        logger.info('Binding pipeline config with - [%s]', p4_name)
        self.interface.bind_pipeline_config(self.bfrt_info.p4_name_get())

        # self.digest_thread = Thread(target=self.receive_digests)
        self.digest_thread = None

    def start_digest_listeners(self):
        logger.info('Tofino currently not supporting digests')
        pass

    def stop_digest_listeners(self):
        self.interface._tear_down_stream()
        logger.info('Tofino currently not supporting digests')
        pass

    def get_table_entry(self, table_name, action_name, match_fields,
                        action_params, ingress_class=True):
        raise NotImplementedError

    def add_data_forward(self, dst_mac, ingress_port):
        raise NotImplementedError

    def del_data_forward(self, dst_mac):
        raise NotImplementedError

    def add_data_inspection(self, dev_id, dev_mac):
        raise NotImplementedError

    def del_data_inspection(self, dev_id, dev_mac):
        raise NotImplementedError

    def build_device_config(self):
        """
        Builds the device config for Tofino
        """
        raise NotImplementedError

    def master_arbitration_update(self):
        logger.info('Master arbitration not implemented on - [%s]',
                    self.grpc_addr)
        # request = bfruntime_pb2.StreamMessageRequest()
        # request.arbitration.device_id = self.device_id
        # request.arbitration.election_id.high = 0
        # request.arbitration.election_id.low = 1
        # self.requests_stream.put(request)

    def set_forwarding_pipeline_config(self, device_config):
        raise NotImplementedError

    def write_table_entry(self, **kwargs):
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
        # TODO - determine how to clone on TNA
        pass

    def delete_clone_entries(self, pre_entry):
        # TODO - determine how to clone on TNA
        pass

    def read_counters(self, counter_id=None, index=None):
        # TODO - determine how to count on TNA
        raise NotImplementedError

    def reset_counters(self, counter_id=None, index=None):
        # TODO - determine how to count on TNA
        raise NotImplementedError

    def write_digest_entry(self, digest_entry):
        # TODO - determine how to digest on TNA
        pass

    def digest_list_ack(self, digest_ack):
        # TODO - determine how to digest on TNA
        pass

    def digest_list(self):
        # TODO - determine how to digest on TNA
        pass

    # TODO - determine if this is available or even necessary on TNA
    def write_multicast_entry(self, hosts):
        self.write_arp_flood()

    def write_arp_flood(self):
        """
        arp_flood_t has not been implemented in core_tna.p4
        :return:
        """
        pass

    def get_table(self, name):
        return self.bfrt_info.table_get(name)

    def get_table_id(self, name):
        table = self.get_table(name)
        if table:
            logger.debug('table id - [%s]', table.info.id)
            return table.info.id

    def insert_table_entry(self, table_name, action_name, key_fields=None,
                           data_fields=None):
        """
        Insert a new table entry
        @param table_name : Table name.
        @param action_name : Action name.
        @param key_fields : List of bfrt_grpc.client.KeyTuple objects.
        @param data_fields : List of bfrt_grpc.client.DataTuple objects.
        """

        table = self.get_table(table_name)
        if table:
            key = table.make_key(key_fields)
            data = table.make_data(data_fields, action_name)
            logger.info('Inserting keys - [%s], data - [%s] into table [%s]',
                        key_fields, data_fields, table_name)
            table.entry_add(self.target, [key], [data])

    def delete_table_entry(self, table_name, key_fields=None):
        """
        Delete an existing table entry
        @param table_name : Table name.
        @param key_fields : List of bfrt_grpc.client.KeyTuple objects.
        """
        table = self.get_table(table_name)
        if table:
            key = table.make_key(key_fields)
            table.entry_del(self.target, [key])


def parseGrpcErrorBinaryDetails(grpc_error):
    if grpc_error.code() != grpc.StatusCode.UNKNOWN:
        return None

    error = None
    # The gRPC Python package does not have a convenient way to access the
    # binary details for the error: they are treated as trailing metadata.
    for meta in grpc_error.trailing_metadata():
        if meta[0] == "grpc-status-details-bin":
            error = status_pb2.Status()
            error.ParseFromString(meta[1])
            break
    if error is None:  # no binary details field
        return None
    if len(error.details) == 0:
        # binary details field has empty Any details repeated field
        return None

    indexed_p4_errors = []
    for idx, one_error_any in enumerate(error.details):
        p4_error = bfruntime_pb2.Error()
        if not one_error_any.Unpack(p4_error):
            return None
        if p4_error.canonical_code == code_pb2.OK:
            continue
        indexed_p4_errors += [(idx, p4_error)]
    return indexed_p4_errors


def printGrpcError(grpc_error):
    status_code = grpc_error.code()
    logger.error("gRPC Error %s %s",
                 grpc_error.details(),
                 status_code.name)

    if status_code != grpc.StatusCode.UNKNOWN:
        return
    bfrt_errors = parseGrpcErrorBinaryDetails(grpc_error)
    if bfrt_errors is None:
        return
    logger.error("Errors in batch:")
    for idx, bfrt_error in bfrt_errors:
        code_name = code_pb2._CODE.values_by_number[
            bfrt_error.canonical_code].name
        logger.error("\t* At index %d %s %s\n",
                     idx, code_name, bfrt_error.message)
    return bfrt_errors
