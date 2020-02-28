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


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   ********************
*************************************************************************/

control TpsEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply {

     }
}

/*************************************************************************
****************  C O R E   E G R E S S   P R O C E S S I N G   ********************
*************************************************************************/

control TpsCoreEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    action data_inspect_packet(bit<32> switch_id) {

        hdr.int_meta_3.setValid();
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + ((bit<16>)hdr.int_header.meta_len * 4);
        hdr.int_shim.length = hdr.int_shim.length + (bit<8>)hdr.int_header.meta_len;
        hdr.int_header.remaining_hop_cnt = hdr.int_header.remaining_hop_cnt - 1;
        hdr.int_meta_3.switch_id = switch_id;

    }

    table data_inspection_t {
        key = {
            hdr.ethernet.src_mac: exact;
        }
        actions = {
            data_inspect_packet;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        data_inspection_t.apply();
    }
}
/*************************************************************************
***********************  D E P A R S E R  ********************************
*************************************************************************/

control TpsDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.int_shim);
        packet.emit(hdr.int_header);
        packet.emit(hdr.int_meta_3);
        packet.emit(hdr.int_meta_2);
        packet.emit(hdr.int_meta);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
    }
}
