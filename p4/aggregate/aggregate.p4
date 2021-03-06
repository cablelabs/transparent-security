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
#include <v1model.p4>

/* TPS includes */
#include "../include/tps_consts.p4"
#include "../include/tps_headers.p4"
#include "../include/tps_parser.p4"
#include "../include/tps_checksum.p4"
#include "../include/tps_egress.p4"

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   ********************
*************************************************************************/

control TpsAggIngress(inout headers hdr,
                      inout metadata meta,
                      inout standard_metadata_t standard_metadata) {

    counter(MAX_DEVICE_ID, CounterType.packets_and_bytes) forwardedPackets;

    action pack_meta_tcp() {
        meta.dst_port = hdr.tcp.dst_port;
    }

    action pack_meta_udp() {
        meta.dst_port = hdr.udp_int.dst_port;
    }

    action pack_meta_ipv4() {
        meta.ipv6_addr = 0;
        meta.ipv4_addr = hdr.ipv4.dstAddr;
    }

    action pack_meta_ipv6() {
        meta.ipv4_addr = 0;
        meta.ipv6_addr = hdr.ipv6.dstAddr;
    }

    action data_drop() {
        mark_to_drop(standard_metadata);
    }

    table data_drop_t {
        key = {
            hdr.ethernet.src_mac: exact;
            meta.ipv4_addr: exact;
            meta.ipv6_addr: exact;
            meta.dst_port: exact;
        }
        actions = {
            data_drop;
            NoAction;
        }
        size = TABLE_SIZE;
        default_action = NoAction();
    }

    action data_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    table data_forward_t {
        key = {
            hdr.ethernet.dst_mac: exact;
        }
        actions = {
            data_forward;
            NoAction;
        }
        size = TABLE_SIZE;
        default_action = NoAction();
    }

    action add_switch_id(bit<32> switch_id) {
        hdr.int_meta_2.setValid();
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + BYTES_PER_SHIM * INT_SHIM_HOP_SIZE;
        hdr.udp_int.len = hdr.udp_int.len + SWITCH_ID_HDR_BYTES;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + BYTES_PER_SHIM * INT_SHIM_HOP_SIZE;
        hdr.int_shim.length = hdr.int_shim.length + INT_SHIM_HOP_SIZE;
        hdr.int_header.remaining_hop_cnt = hdr.int_header.remaining_hop_cnt - 1;
        hdr.int_meta_2.switch_id = switch_id;
    }

    table add_switch_id_t {
        key = {
            hdr.udp_int.dst_port: exact;
        }
        actions = {
            add_switch_id;
            NoAction;
        }
        size = TABLE_SIZE;
        default_action = NoAction();
    }

    action data_inspect_packet(bit<32> device, bit<32> switch_id) {
        hdr.int_shim.setValid();
        hdr.int_header.setValid();
        hdr.int_meta.setValid();

        hdr.int_shim.npt = INT_SHIM_NPT_UDP_FULL_WRAP;
        hdr.int_shim.type = INT_SHIM_TYPE;
        hdr.int_shim.length = INT_SHIM_BASE_SIZE;

        hdr.int_header.ver = INT_VERSION;
        hdr.int_header.domain_id = INT_SHIM_DOMAIN_ID;
        hdr.int_header.meta_len = INT_META_LEN;
        hdr.int_header.instr_bit_0 = TRUE;
        hdr.int_header.ds_instr_0 = TRUE;
        hdr.int_header.ds_flags_1 = TRUE;
        hdr.int_header.remaining_hop_cnt = MAX_HOPS;

        hdr.int_meta.switch_id = switch_id;
        hdr.int_meta.orig_mac = hdr.ethernet.src_mac;

        forwardedPackets.count(device);
    }

    action data_inspect_packet_ipv4() {
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.int_shim.next_proto = hdr.ipv4.protocol;
        hdr.ipv4.protocol = TYPE_UDP;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + ((bit<16>)hdr.int_shim.length * BYTES_PER_SHIM * INT_SHIM_HOP_SIZE) + UDP_HDR_BYTES;
    }

    action data_inspect_packet_ipv6() {
        hdr.int_shim.next_proto = hdr.ipv6.next_hdr_proto;
        hdr.ipv6.next_hdr_proto = TYPE_UDP;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + IPV6_HDR_BYTES + ((bit<16>)hdr.int_shim.length * BYTES_PER_SHIM * INT_SHIM_HOP_SIZE) + UDP_HDR_BYTES;
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

    action insert_udp_int_for_udp() {
        hdr.udp.setValid();
        hdr.udp.src_port = hdr.udp_int.src_port;
        hdr.udp.dst_port = hdr.udp_int.dst_port;
        hdr.udp.len = hdr.udp_int.len;
        hdr.udp_int.src_port = UDP_INT_SRC_PORT;
        hdr.udp_int.dst_port = UDP_INT_DST_PORT;
        hdr.udp_int.len = hdr.udp.len + ((bit<16>)hdr.int_shim.length * BYTES_PER_SHIM * INT_SHIM_HOP_SIZE) + UDP_HDR_BYTES;
    }

    action insert_udp_int_for_tcp_ipv4() {
        hdr.udp_int.setValid();
        hdr.udp_int.src_port = UDP_INT_SRC_PORT;
        hdr.udp_int.dst_port = UDP_INT_DST_PORT;
        hdr.udp_int.len = hdr.ipv4.totalLen - IPV4_HDR_BYTES;
    }

    action insert_udp_int_for_tcp_ipv6() {
        hdr.udp_int.setValid();
        hdr.udp_int.src_port = UDP_INT_SRC_PORT;
        hdr.udp_int.dst_port = UDP_INT_DST_PORT;
        hdr.udp_int.len = hdr.ipv6.payload_len - IPV6_HDR_BYTES;
    }

    action control_drop() {
        mark_to_drop(standard_metadata);;
    }

    action generate_learn_notification() {
        digest<mac_learn_digest>((bit<32>) 1024,
            { hdr.arp.src_mac,
              standard_metadata.ingress_port
            });
    }

    action arp_flood() {
        standard_metadata.mcast_grp = 1;
    }

    table arp_flood_t {
        key = {
            hdr.ethernet.dst_mac: exact;
        }
        actions = {
            arp_flood;
            NoAction;
        }
        default_action = NoAction();
    }

     apply {
        if (hdr.arp.isValid()) {
            generate_learn_notification();
            if (hdr.arp.opcode == 1) {
                arp_flood_t.apply();
            } else if (hdr.arp.opcode == 2) {
                data_forward_t.apply();
            }
        } else if (standard_metadata.egress_spec != DROP_PORT) {
            if (hdr.int_shim.isValid()) {
                // Add switch ID into existing INT data
                add_switch_id_t.apply();
            } else {
                // Pack metadata with original header values for data drop
                if (hdr.udp_int.isValid()) {
                    pack_meta_udp();
                } else if (hdr.tcp.isValid()) {
                    pack_meta_tcp();
                }
                if (hdr.ipv4.isValid()) {
                    pack_meta_ipv4();
                } else if (hdr.ipv6.isValid()) {
                    pack_meta_ipv6();
                }

                // Check to see if need to add INT
                data_inspection_t.apply();

                // Add IP & Protocol specific data to new INT data
                if (hdr.int_shim.isValid()) {
                    if (hdr.ipv4.isValid()) {
                        data_inspect_packet_ipv4();
                        if (hdr.udp_int.isValid()) {
                            insert_udp_int_for_udp();
                        } else if (hdr.tcp.isValid()) {
                            insert_udp_int_for_tcp_ipv4();
                        }
                    }
                    else if (hdr.ipv6.isValid()) {
                        data_inspect_packet_ipv6();
                        if (hdr.udp_int.isValid()) {
                            insert_udp_int_for_udp();
                        } else if (hdr.tcp.isValid()) {
                            insert_udp_int_for_tcp_ipv6();
                        }
                    }
                }
            }
            data_forward_t.apply();
        }
        data_drop_t.apply();
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
    TpsAggDeparser()
) main;
