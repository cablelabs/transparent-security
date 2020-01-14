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
from scapy.all import Packet
from scapy import fields


class GatewayINTHeader(Packet):
    """
    This class represents the INT data being placed onto the packets to help
    generating and parsing
    """
    name = "GW_INT_HDR"
    fields_desc = [
        fields.LongField('gw_int_header', 0),
    ]


class GatewayINTInspect(Packet):
    """
    This class represents the INT data being placed onto the packets to help
    generating and parsing
    """
    name = "GW_INT"
    fields_desc = [
        fields.MACField('src_mac', 'ff:ff:ff:ff:ff:ff'),
        fields.ShortField('proto_id', 0x800),
    ]


class SwitchINTHeader(Packet):
    """
    This class represents the INT data being placed onto the packets to help
    generating and parsing
    """
    name = "SW_INT_HDR"
    fields_desc = [
        fields.LongField('sw_int_header', 0),
    ]


class SwitchINTInspect(Packet):
    """
    This class represents the INT data being placed onto the packets to help
    generating and parsing
    """
    name = "SW_INT"
    fields_desc = [
        fields.IntField('switch_id', 0),
    ]
