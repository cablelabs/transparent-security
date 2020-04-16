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
import logging
import re

import google.protobuf.text_format
from p4.config.v1 import p4info_pb2
from p4.v1 import p4runtime_pb2

from trans_sec.utils.convert import encode

logger = logging.getLogger('helper')


class P4InfoHelper(object):
    def __init__(self, p4_info_filepath):
        p4info = p4info_pb2.P4Info()
        # Load the p4info file into a skeleton P4Info object
        with open(p4_info_filepath) as p4info_f:
            google.protobuf.text_format.Merge(p4info_f.read(), p4info)
        self.p4info = p4info

    def get(self, entity_type, name=None, entity_id=None):
        if name is not None and entity_id is not None:
            raise AssertionError("name or id must be None")

        for o in getattr(self.p4info, entity_type):
            pre = o.preamble
            if name:
                if pre.name == name or pre.alias == name:
                    return o
            else:
                if pre.id == entity_id:
                    return o

        if name:
            raise AttributeError(
                "Could not find %r of type %s" % (name, entity_type))
        else:
            raise AttributeError(
                "Could not find id %r of type %s" % (entity_id, entity_type))

    def get_id(self, entity_type, name):
        return self.get(entity_type, name=name).preamble.id

    def get_name(self, entity_type, entity_id):
        return self.get(entity_type, entity_id=entity_id).preamble.name

    def get_alias(self, entity_type, entity_id):
        return self.get(entity_type, entity_id=entity_id).preamble.alias

    def __getattr__(self, attr):
        # Synthesize convenience functions for name to id lookups for top-level
        # entities
        # e.g. get_tables_id(name_string) or get_actions_id(name_string)
        m = re.search(r"^get_(\w+)_id$", attr)
        if m:
            primitive = m.group(1)
            return lambda name: self.get_id(primitive, name)

        # Synthesize convenience functions for id to name lookups
        # e.g. get_tables_name(id) or get_actions_name(id)
        m = re.search(r"^get_(\w+)_name$", attr)
        if m:
            primitive = m.group(1)
            return lambda prim_id: self.get_name(primitive, prim_id)

        raise AttributeError(
            "%r object has no attribute %r" % (self.__class__, attr))

    def get_match_field(self, table_name, name=None, field_id=None):
        for t in self.p4info.tables:
            pre = t.preamble
            if pre.name == table_name:
                for mf in t.match_fields:
                    if name is not None:
                        if mf.name == name:
                            return mf
                    elif field_id is not None:
                        if mf.id == field_id:
                            return mf
        raise AttributeError("%r has no attribute %r" % (
            table_name, name if name is not None else field_id))

    def get_match_field_id(self, table_name, match_field_name):
        return self.get_match_field(table_name, name=match_field_name).id

    def get_match_field_name(self, table_name, match_field_id):
        return self.get_match_field(table_name, field_id=match_field_id).name

    def get_match_field_pb(self, table_name, match_field_name, value):
        logger.info(
            'Retrieving match field on table name - [%s], match field - [%s], '
            'value - [%s]', table_name, match_field_name, value)

        p4info_match = self.get_match_field(table_name, match_field_name)
        bit_width = p4info_match.bitwidth
        p4runtime_match = p4runtime_pb2.FieldMatch()
        p4runtime_match.field_id = p4info_match.id
        match_type = p4info_match.match_type

        logger.info(
            'Encoding value [%s] for exact match with bitwidth - [%s]',
            value, bit_width)

        if match_type == p4info_pb2.MatchField.EXACT:
            logger.info('Encoding for EXACT matches')
            exact = p4runtime_match.exact
            exact.value = encode(value, bit_width)
        elif match_type == p4info_pb2.MatchField.LPM:
            logger.info('Encoding for LPM matches')
            lpm = p4runtime_match.lpm
            lpm.value = encode(value[0], bit_width)
            lpm.prefix_len = value[1]
        elif match_type == p4info_pb2.MatchField.TERNARY:
            logger.info('Encoding for TERNARY matches')
            ternary = p4runtime_match.ternary
            ternary.value = encode(value[0], bit_width)
            ternary.mask = encode(value[1], bit_width)
        elif match_type == p4info_pb2.MatchField.RANGE:
            logger.info('Encoding for RANGE matches')
            range_match = p4runtime_match.range
            range_match.low = encode(value[0], bit_width)
            range_match.high = encode(value[1], bit_width)
        else:
            raise Exception("Unsupported match type with type %r" % match_type)
        return p4runtime_match

    @staticmethod
    def get_match_field_value(match_field):
        match_type = match_field.WhichOneof("field_match_type")
        if match_type == 'valid':
            return match_field.valid.value
        elif match_type == 'exact':
            return match_field.exact.value
        elif match_type == 'lpm':
            return match_field.lpm.value, match_field.lpm.prefix_len
        elif match_type == 'ternary':
            return match_field.ternary.value, match_field.ternary.mask
        elif match_type == 'range':
            return match_field.range.low, match_field.range.high
        else:
            raise Exception("Unsupported match type with type %r" % match_type)

    def get_action_param(self, action_name, name=None, action_id=None):
        action = None
        for action in self.p4info.actions:
            pre = action.preamble
            if pre.name == action_name:
                for param in action.params:
                    if name is not None:
                        if param.name == name:
                            return param
                    elif action_id is not None:
                        if param.id == action_id:
                            return param
        if action:
            raise AttributeError("action %r has no param %r, (has: %r)" % (
                action_name, name if name is not None else action_id,
                action.params))
        else:
            raise AttributeError("action %r has no param %r" % (
                action_name, name if name is not None else action_id))

    def get_action_param_id(self, action_name, param_name):
        return self.get_action_param(action_name, name=param_name).id

    def get_action_param_name(self, action_name, param_id):
        return self.get_action_param(action_name, action_id=param_id).name

    def get_action_param_pb(self, action_name, param_name, value):
        logger.info(
            'Retrieving action param for action - [%s], param - [%s], '
            'value - [%s]', action_name, param_name, value)
        p4info_param = self.get_action_param(action_name, param_name)
        p4runtime_param = p4runtime_pb2.Action.Param()
        p4runtime_param.param_id = p4info_param.id
        p4runtime_param.value = encode(value, p4info_param.bitwidth)
        return p4runtime_param

    def build_table_entry(self, table_name, match_fields=None,
                          default_action=False, action_name=None,
                          action_params=None, priority=None):
        logger.info(
            'Building table entry to table [%s] with match_fields - [%s] '
            'action - [%s] and params - [%s]',
            table_name, match_fields, action_name, action_params)
        table_entry = p4runtime_pb2.TableEntry()
        table_entry.table_id = self.get_tables_id(table_name)
        logger.debug('Table ID - [%s]', table_entry.table_id)

        if priority is not None:
            table_entry.priority = priority

        if match_fields:
            table_entry.match.extend([
                self.get_match_field_pb(table_name, match_field_name, value)
                for match_field_name, value in match_fields.items()
            ])

        if default_action:
            table_entry.is_default_action = True

        if action_name:
            action = table_entry.action.action
            action.action_id = self.get_actions_id(action_name)
            if action_params:
                logger.info('Action params - [%s]', action_params)
                action.params.extend([
                    self.get_action_param_pb(action_name, field_name, value)
                    for field_name, value in action_params.items()
                ])
        return table_entry

    @staticmethod
    def reset_counter(counter_id, index):
        logger.info('Resetting counter with ID - [%s] and index - [%s]',
                    counter_id, index)
        counter_entry = p4runtime_pb2.CounterEntry()
        if counter_id is not None:
            counter_entry.counter_id = counter_id
        else:
            counter_entry.counter_id = 0
        if index is not None:
            counter_entry.index.index = index
        counter_entry.data.byte_count = 0
        counter_entry.data.packet_count = 0

    @staticmethod
    def build_clone_entry(clone_egress):
        logger.info('Building clone entry with egress_port value of - [%s]',
                    clone_egress)
        pre_entry = p4runtime_pb2.PacketReplicationEngineEntry()
        clone_session_entry = p4runtime_pb2.CloneSessionEntry()
        clone_session_entry.session_id = 5
        clone_session_entry.replicas.add(egress_port=clone_egress, instance=1)
        pre_entry.clone_session_entry.CopyFrom(clone_session_entry)
        logger.info('Clone entry - [%s]', pre_entry)
        return pre_entry

    def build_digest_entry(self, digest_name):
        digest_entry = p4runtime_pb2.DigestEntry()
        # using name
        digest_entry.digest_id = self.get_digests_id(digest_name)
        # using id directly
        digest_entry.config.max_timeout_ns = 0
        digest_entry.config.max_list_size = 1
        digest_entry.config.ack_timeout_ns = 0
        return digest_entry

    def build_multicast_group_entry(self, mc_group_id, replicas):
        mc_entry = p4runtime_pb2.PacketReplicationEngineEntry()
        mc_entry.multicast_group_entry.multicast_group_id = mc_group_id
        for replica in replicas:
            r = p4runtime_pb2.Replica()
            r.egress_port = int(replica['egress_port'])
            r.instance = int(replica['instance'])
            mc_entry.multicast_group_entry.replicas.extend([r])
        return mc_entry
