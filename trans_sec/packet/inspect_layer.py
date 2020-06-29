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
    XShortField, ETHER_TYPES
from scapy import fields

import trans_sec.consts


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
        fields.BitField('ver', 2, 4),
        fields.BitField('rep', 0, 2),
        fields.BitField('d', 0, 1),
        fields.BitField('e', 0, 1),
        fields.BitField('m', 0, 1),
        fields.BitField('reserved', 0, 10),
        fields.BitField('meta_len', 1, 5),
        fields.ByteField('remaining_hop_cnt', 0),
        fields.BitField('instr_bit_0', 1, 1),
        fields.BitField('instr_bit_bal', 0, 15),
        fields.BitField('domain_id', 0, 16),
        fields.BitField('ds_instr_0', 1, 1),
        fields.BitField('ds_instr_bal', 0, 15),
        fields.BitField('ds_flags_0', 0, 1),
        fields.BitField('ds_flags_1', 1, 1),
        fields.BitField('ds_flags_bal', 0, 14),
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


class EthInt(Packet):
    name = "UDP_INT"
    fields_desc = [
        fields.MACField('dst', 0),
        fields.MACField('src', 0),
        fields.XShortEnumField("type", 0x9000, ETHER_TYPES),
    ]


class UdpInt(Packet):
    name = "UDP_INT"
    fields_desc = [
        ShortEnumField("sport", trans_sec.consts.UDP_INT_SRC_PORT,
                       UDP_SERVICES),
        ShortEnumField("dport", trans_sec.consts.UDP_INT_DST_PORT,
                       UDP_SERVICES),
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


class TelemetryReport(Packet):
    """
    This class represents the INT header data being placed onto the packets to
    help generating and parsing
    """
    fields_desc = [
        fields.BitField('ver', 0, 4),
        fields.BitField('hw_id', 0, 6),
        fields.BitField('sequence_no', 0, 22),
        fields.IntField('node_id', 0),
        fields.BitField('rep_type', 0, 4),
        fields.BitField('in_type', 0, 4),
        fields.ByteField('rpt_len', 0),
        fields.ByteField('md_len', 0),
        fields.BitField('d', 0, 1),
        fields.BitField('q', 0, 1),
        fields.BitField('f', 0, 1),
        fields.BitField('i', 0, 1),
        fields.BitField('reserved', 0, 4),
        fields.ShortField('rep_md_bits', 0),
        fields.ShortField('domain_id', 0),
        fields.ShortField('ds_mdb_bits', 0),
        fields.ShortField('ds_mds_bits', 0),
        fields.IntField('var_opt_md', 0)
    ]
