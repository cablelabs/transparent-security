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

    action drop() {
        mark_to_drop(standard_metadata);
    }

    apply {
        if(IS_REPLICATED(standard_metadata)) {
            if (standard_metadata.egress_port == standard_metadata.ingress_port) {
                drop();
            }
        }
    }
}

/*************************************************************************
***********************  D E P A R S E R  ********************************
*************************************************************************/

control TpsDeparser(packet_out packet, in headers hdr) {
    apply {
        /* For Telemetry Report Packets */
        packet.emit(hdr.trpt_eth);
        packet.emit(hdr.trpt_ipv4);
        packet.emit(hdr.trpt_ipv6);
        packet.emit(hdr.trpt_udp);
        packet.emit(hdr.trpt_hdr);

        /* For Standard and INT Packets */
        packet.emit(hdr.ethernet);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.udp_int);

        packet.emit(hdr.int_shim);
        packet.emit(hdr.int_header);
        packet.emit(hdr.int_meta_3);
        packet.emit(hdr.int_meta_2);
        packet.emit(hdr.int_meta);

        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
    }
}
