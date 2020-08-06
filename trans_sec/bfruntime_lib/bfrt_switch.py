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

import tofino.bfrt_grpc.client as bfrt_client
import logging
from abc import ABC

import grpc
from google.rpc import code_pb2, status_pb2
from tofino.bfrt_grpc import bfruntime_pb2_grpc, bfruntime_pb2

from trans_sec.switch import SwitchConnection, GrpcRequestLogger, IterableQueue

MSG_LOG_MAX_LEN = 1024

logger = logging.getLogger('switch')


class BFRuntimeSwitch(SwitchConnection, ABC):
    def __init__(self, sw_info, proto_dump_file=None, client_id=0):
        super(BFRuntimeSwitch, self).__init__(sw_info)
        channel = grpc.insecure_channel(self.grpc_addr)
        if proto_dump_file:
            logger.info('Adding interceptor with file - [%s] to device [%s]',
                        proto_dump_file, self.grpc_addr)
            interceptor = GrpcRequestLogger(proto_dump_file)
            channel = grpc.intercept_channel(channel, interceptor)

        logger.info('Creating client stub to address - [%s]', self.grpc_addr)
        self.client_id = client_id
        self.client_stub = bfruntime_pb2_grpc.BfRuntimeStub(channel)
        self.requests_stream = IterableQueue()
        self.stream_msg_resp = self.client_stub.StreamChannel(iter(
            self.requests_stream))
        self.proto_dump_file = proto_dump_file

        logger.info('Connecting to the BFRT server @ [%s], client_id [%s],'
                    ' device_id [%s]', self.grpc_addr, self.client_id,
                    self.device_id)
        self.interface = bfrt_client.ClientInterface(
            self.grpc_addr, client_id=self.client_id, device_id=self.device_id)
        self.bfrt_info = self.interface.bfrt_info_get("tna_32q_2pipe")
        self.bfrt_info = None

        # self.digest_thread = Thread(target=self.receive_digests)

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
        arp_flood_t has not been implemented in core-tna.p4
        :return:
        """
        pass

    def get_table_local(self, table_name):
        for dict_table_name, table in self.bfrt_info.table_dict.iteritems():
            if dict_table_name == table_name:
                return table.id

    def get_table(self, name):
        if self.bfrt_info:
            return self.get_table_local(name)
        req = bfruntime_pb2.ReadRequest()
        req.client_id = self.client_id
        req.target.device_id = self.device_id

        object_id = req.entities.add().object_id
        object_id.table_object.table_name = name

        for rep in self.client_stub.Read(req):
            return rep.entities[0].object_id.id

    def add_target_data_to_request(self, req):
        target = bfrt_client.Target(device_id=self.device_id, pipe_id=0xffff)
        req.target.device_id = target.device_id_
        req.target.pipe_id = target.pipe_id_
        req.target.direction = target.direction_
        req.target.prsr_id = target.prsr_id_

    def insert_table_entry(self, table_name, key_fields=None, action_name=None,
                           data_fields=[]):
        """
        Insert a new table entry
            @param table_name : Table name.
            @param key_fields : List of (name, value, [mask]) tuples.
            @param action_name : Action name.
            @param data_fields : List of (name, value) tuples.
        """

        req = bfruntime_pb2.WriteRequest()
        self.add_target_data_to_request(req)

        return self.write(
            self.entry_write_req_make(req, table_name, [key_fields],
                                      [action_name], [data_fields],
                                      bfruntime_pb2.Update.INSERT))

    def entry_write_req_make(self, req, table_name,
                             key_fields=[], action_names=[], data_fields=[],
                             update_type=bfruntime_pb2.Update.INSERT,
                             modify_inc_type=None):
        if self.get_table(table_name) is None:
            logger.warning("Table %s not found", table_name)
            return

        if key_fields and action_names and data_fields:
            assert (len(key_fields) == len(action_names) == len(data_fields));
        for idx in range(len(key_fields)):
            update = req.updates.add()
            update.type = update_type
            table_entry = update.entity.table_entry
            table_entry.table_id = self.get_table(table_name)
            table_entry.is_default_entry = False
            if modify_inc_type:
                table_entry.table_mod_inc_flag.type = modify_inc_type

            if key_fields and key_fields[idx]:
                self.set_table_key(table_entry, key_fields[idx], table_name)
            if action_names and data_fields:
                self.set_table_data(table_entry, action_names[idx],
                                    data_fields[idx], table_name)
        return req

    def write(self, req):
        # req.client_id = self.device_id
        try:
            self.client_stub.Write(req)
        except grpc.RpcError as e:
            printGrpcError(e)
            raise e

    def read(self, req):
        try:
            return self.client_stub.Read(req)
        except grpc.RpcError as e:
            printGrpcError(e)
            raise e

    def set_table_key(self, table, key_fields, table_name):
        """
        Sets the key for a bfn::TableEntry object
        @param table : bfn::TableEntry object.
        @param key_fields: List of (name, value, [mask]) tuples
        @param table_name: The name of the table
        """
        if table is None:
            logger.warning("Invalid TableEntry object.")
            return

        for field in key_fields:
            field_id = self.get_key_field(table_name, field.name)
            if field_id is None:
                logger.error("Data key %s not found.", field.name)
            key_field = table.key.fields.add()
            key_field.field_id = field_id
            if field.mask:
                key_field.ternary.value = field.value
                key_field.ternary.mask = field.mask
            elif field.prefix_len:
                key_field.lpm.value = field.value
                key_field.lpm.prefix_len = field.prefix_len
            elif field.low or field.high:
                key_field.range.low = field.low
                key_field.range.high = field.high
            else:
                key_field.exact.value = field.value

    def get_key_local(self, table_name, field_name):
        table_obj = self.bfrt_info.table_dict[table_name]
        for field_name_, key_ in table_obj.key_dict.iteritems():
            if field_name_ == field_name:
                return key_.id
        return 0

    def get_key_field(self, table_name, field_name):
        """ Get key field id for a given table and field. """
        if self.bfrt_info:
            return self.get_key_local(table_name, field_name)
        req = bfruntime_pb2.ReadRequest()
        req.client_id = self.client_id
        req.target.device_id = self.device_id

        object_id = req.entities.add().object_id
        object_id.table_object.table_name = table_name
        object_id.table_object.key_field_name.field = field_name
        for rep in self.client_stub.Read(req):
            return rep.entities[0].object_id.id

    def get_data_field_local(self, table_name, action_name, field_name):
        table_obj = self.bfrt_info.table_dict[table_name]
        if action_name is not None:
            for action_name_, action_ in table_obj.action_dict.iteritems():
                if action_name_ == action_name:
                    for field_name_, data_ in action_.data_dict.iteritems():
                        if field_name_ == field_name:
                            return data_.id
        for field_name_, data_ in table_obj.data_dict.iteritems():
            if field_name_ == field_name:
                return data_.id
        return 0

    def get_data_field(self, table_name, action_name, field_name):
        """ Get data field id for a given table, action and field. """
        if self.bfrt_info:
            return self.get_data_field_local(table_name, action_name,
                                             field_name)
        req = bfruntime_pb2.ReadRequest()
        req.client_id = self.client_id
        req.target.device_id = self.device_id

        object_id = req.entities.add().object_id
        object_id.table_object.table_name = table_name
        if action_name is not None:
            object_id.table_object.data_field_name.action = action_name
        object_id.table_object.data_field_name.field = field_name
        for rep in self.client_stub.Read(req):
            return rep.entities[0].object_id.id

    def get_action_local(self, table_name, action_name):
        table_obj = self.bfrt_info.table_dict[table_name]
        for action_name_, action_ in table_obj.action_dict.iteritems():
            if action_name_ == action_name:
                return action_.id

    def get_action(self, table_name, action_name):
        """ Get action id for a given table and action. """
        if self.bfrt_info:
            return self.get_table_local(table_name)
        req = bfruntime_pb2.ReadRequest()
        req.client_id = self.client_id
        req.target.device_id = self.device_id

        object_id = req.entities.add().object_id
        object_id.table_object.table_name = table_name
        object_id.table_object.action_name.action = action_name

        for rep in self.client_stub.Read(req):
            return rep.entities[0].object_id.id

    def set_table_data(self, table, action, data_fields, table_name):
        """ Sets the data for a bfn::TableEntry object
            @param table : bfn::TableEntry object.
            @param ation : Name of the action
            @param data_fields: List of (name, value) tuples.
        """
        if action:
            table.data.action_id = self.get_action(table_name, action)

        if data_fields:
            for field in data_fields:
                data_field = table.data.fields.add()
                data_field.field_id = self.get_data_field(
                    table_name, action, field.name)
                if field.stream:
                    data_field.stream = field.stream
                elif field.float_val:
                    data_field.float_val = field.float_val
                elif field.str_val:
                    data_field.str_val = field.str_val
                elif field.bool_val:
                    data_field.bool_val = field.bool_val
                elif field.int_arr_val:
                    data_field.int_arr_val.val.extend(field.int_arr_val)
                elif field.bool_arr_val:
                    data_field.bool_arr_val.val.extend(field.bool_arr_val)


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
