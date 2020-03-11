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
from scapy.all import Packet, ShortEnumField, UDP_SERVICES, ShortField, \
    XShortField
from scapy import fields


class IntShim(Packet):
    """
    This class represents the INT shim being placed onto the packets to help
    generating and parsing
    """
    fields_desc = [
        fields.BitField('type', 0, 4),
        fields.BitField('npt', 0, 2),
        fields.BitField('res1', 0, 2),
        fields.ByteField('length', 0),
        fields.ByteField('res2', 0),
        fields.ByteField('next_proto', 0),
    ]


class IntHeader(Packet):
    """
    This class represents the INT header data being placed onto the packets to
    help generating and parsing
    """
    fields_desc = [
        fields.BitField('ver', 0, 4),
        fields.BitField('rep', 0, 2),
        fields.BitField('d', 0, 1),
        fields.BitField('e', 0, 1),
        fields.BitField('m', 0, 1),
        fields.BitField('reserved', 0, 10),
        fields.BitField('meta_len', 0, 5),
        fields.ByteField('remaining_hop_cnt', 0),
        fields.BitField('instr_bitmap', 0, 16),
        fields.BitField('domain_id', 0, 16),
        fields.BitField('ds_instructions', 0, 16),
        fields.BitField('ds_flags_1', 0, 1),
        fields.BitField('ds_flags_2', 0, 1),
        fields.BitField('ds_flags_3', 0, 1),
        fields.BitField('ds_flags_13', 0, 13),
    ]


class SourceIntMeta(Packet):
    """
    This class represents the INT metadata being placed onto the packets
    """
    name = "Source_INT_Meta"

    fields_desc = [
        fields.IntField('switch_id', 0),
        fields.MACField('orig_mac', 0),
        fields.BitField('reserved', 0, 16),
    ]


class UdpInt(Packet):
    name = "UDP_INT"
    fields_desc = [
        ShortEnumField("sport", 53, UDP_SERVICES),
        ShortEnumField("dport", 53, UDP_SERVICES),
        ShortField("len", None),
        XShortField("chksum", None),
    ]


class IntMeta(Packet):
    """
    This class represents the INT metadata being placed onto the packets
    """
    fields_desc = [
        fields.IntField('switch_id', 0),
    ]


class IntMeta1(IntMeta):
    """
    This class represents the first INT metadata being placed onto the packets
    """
    name = "INT_META_1"


class IntMeta2(IntMeta):
    """
    This class represents the second INT metadata being placed onto the packets
    """
    name = "INT_META_2"
