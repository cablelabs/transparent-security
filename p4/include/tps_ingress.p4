/*
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
*/
/* -*- P4_16 -*- */

control debug_meta(in metadata meta, in headers hdr)
{
    table dbg_table {
        key = {
           hdr.gw_int.src_mac: exact;
           hdr.gw_int.proto_id: exact;
           hdr.sw_int.switch_id: exact;
           hdr.ipv4.srcAddr: exact;
           hdr.ipv4.dstAddr: exact;
           hdr.udp.dst_port: exact;
           hdr.ethernet.dst_mac: exact;
           hdr.ipv4.identification: exact;
        }
        actions = { NoAction; }
        const default_action = NoAction();
    }
    apply {
        dbg_table.apply();
    }
}
