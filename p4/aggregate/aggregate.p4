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
#include <core.p4>
#include <v1model.p4>

/* TPS includes */
#include <tps_headers.p4>
#include <tps_parser.p4>
#include <tps_checksum.p4>
#include <tps_egress.p4>

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   ********************
*************************************************************************/

control TpsAggIngress(inout headers hdr,
                      inout metadata meta,
                      inout standard_metadata_t standard_metadata) {

    counter(MAX_DEVICE_ID, CounterType.packets_and_bytes) forwardedPackets;

    action data_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.src_mac = hdr.ethernet.dst_mac;
        hdr.ethernet.dst_mac = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table data_forward_ipv4_t {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            data_forward;
            NoAction;
        }
        size = TABLE_SIZE;
        default_action = NoAction();
    }

    table data_forward_ipv6_t {
        key = {
            hdr.ipv6.dstAddr: lpm;
        }
        actions = {
            data_forward;
            NoAction;
        }
        size = TABLE_SIZE;
        default_action = NoAction();
    }

    action data_inspect_packet(bit<32> device, bit<32> switch_id) {
        hdr.int_meta_2.setValid();
        hdr.int_shim.length = hdr.int_shim.length + INT_SHIM_HOP_SIZE;
        hdr.int_header.remaining_hop_cnt = hdr.int_header.remaining_hop_cnt - 1;
        hdr.int_meta_2.switch_id = switch_id;

        hdr.ipv4.totalLen = hdr.ipv4.totalLen + BYTES_PER_SHIM * INT_SHIM_HOP_SIZE;
        hdr.udp_int.len = hdr.udp_int.len + BYTES_PER_SHIM * INT_SHIM_HOP_SIZE;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + BYTES_PER_SHIM * INT_SHIM_HOP_SIZE;
        forwardedPackets.count(device);
    }

    table data_inspection_t {
        key = {
            hdr.ethernet.src_mac: exact;
        }
        actions = {
            data_inspect_packet;
            NoAction;
        }
        size = TABLE_SIZE;
        default_action = NoAction();
    }

    action control_drop() {
        mark_to_drop(standard_metadata);;
    }

    action arp_flood(macAddr_t srcAddr) {
        hdr.ethernet.src_mac = srcAddr;
        standard_metadata.mcast_grp = 1;
    }

    action generate_learn_notification() {
        digest<mac_learn_digest>((bit<32>) 1024,
            { hdr.arp.srcAddr,
              hdr.ethernet.src_mac,
              standard_metadata.ingress_port
            });
    }

    table mac_learn_t {
        key = {
            hdr.ethernet.dst_mac: exact;
        }
        actions = {
            arp_flood;
            NoAction;
        }
        default_action = NoAction();
    }

    action arp_reply(macAddr_t srcAddr, macAddr_t dstAddr, egressSpec_t port) {
        hdr.ethernet.src_mac = srcAddr;
        hdr.ethernet.dst_mac = dstAddr;
        standard_metadata.egress_spec = port;
    }

    table arp_reply_t {
        key = {
            hdr.arp.dstAddr: lpm;
        }
        actions = {
            arp_reply;
            NoAction;
        }
        default_action = NoAction();
    }

     apply {
        if (hdr.arp.isValid()) {
            generate_learn_notification();
            if (hdr.arp.opcode == 1) {
                mac_learn_t.apply();
            }
            else if (hdr.arp.opcode == 2) {
                arp_reply_t.apply();
            }
        } else if (standard_metadata.egress_spec != DROP_PORT) {
            data_inspection_t.apply();
            if (hdr.ipv4.isValid()) {
                data_forward_ipv4_t.apply();
            }
            if (hdr.ipv6.isValid()) {
                data_forward_ipv6_t.apply();
            }
        }
    }
}

/*************************************************************************
***********************  S W I T C H  ************************************
*************************************************************************/

V1Switch(
    TpsAggParser(),
    TpsVerifyChecksum(),
    TpsAggIngress(),
    TpsEgress(),
    TpsComputeChecksum(),
    TpsDeparser()
) main;
