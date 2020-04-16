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

control TpsGwIngress(inout headers hdr,
                     inout metadata meta,
                     inout standard_metadata_t standard_metadata) {

    counter(MAX_DEVICE_ID, CounterType.packets_and_bytes) forwardedPackets;
    counter(MAX_DEVICE_ID, CounterType.packets_and_bytes) droppedPackets;

    action data_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.src_mac = hdr.ethernet.dst_mac;
        hdr.ethernet.dst_mac = dstAddr;
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

    action data_inspect_packet_ipv4(bit<32> device, bit<32> switch_id) {
        hdr.udp_int.setValid();
        hdr.int_shim.setValid();
        hdr.int_header.setValid();
        hdr.int_meta.setValid();

        hdr.udp_int.dst_port = UDP_INT_DST_PORT;

        hdr.int_shim.next_proto = hdr.ipv4.protocol;
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

        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        hdr.ipv4.protocol = TYPE_UDP;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + ((bit<16>)hdr.int_shim.length * BYTES_PER_SHIM * INT_SHIM_HOP_SIZE) + UDP_HDR_BYTES;

        forwardedPackets.count(device);
    }

    action data_inspect_packet_ipv6(bit<32> device, bit<32> switch_id) {
        hdr.udp_int.setValid();
        hdr.int_shim.setValid();
        hdr.int_header.setValid();
        hdr.int_meta.setValid();

        hdr.udp_int.dst_port = UDP_INT_DST_PORT;

        hdr.int_shim.next_proto = hdr.ipv6.next_hdr_proto;
        hdr.int_shim.npt = INT_SHIM_NPT_UDP_FULL_WRAP;
        hdr.int_shim.type = INT_SHIM_TYPE;
        hdr.int_shim.length = INT_SHIM_BASE_SIZE;

        hdr.int_header.ver = INT_VERSION;
        hdr.int_header.domain_id = INT_SHIM_DOMAIN_ID;
        hdr.int_header.meta_len = INT_META_LEN;
        hdr.int_header.instr_bit_0 = TRUE;
        hdr.int_header.ds_instr_0 = TRUE;
        hdr.int_header.ds_flags_0 = FALSE;
        hdr.int_header.ds_flags_1 = TRUE;
        hdr.int_header.remaining_hop_cnt = MAX_HOPS;

        hdr.int_meta.switch_id = switch_id;
        hdr.int_meta.orig_mac = hdr.ethernet.src_mac;

        hdr.ipv6.next_hdr_proto = TYPE_UDP;
        hdr.ipv6.payload_len = hdr.ipv6.payload_len + IPV6_HDR_BYTES + ((bit<16>)hdr.int_shim.length * BYTES_PER_SHIM * INT_SHIM_HOP_SIZE) + UDP_HDR_BYTES;

        forwardedPackets.count(device);
    }

    table data_inspection_t {
        key = {
            hdr.ethernet.src_mac: exact;
            hdr.ethernet.etherType: exact;
        }
        actions = {
            data_inspect_packet_ipv4;
            data_inspect_packet_ipv6;
            NoAction;
        }
        size = TABLE_SIZE;
        default_action = NoAction();
    }

    action insert_udp_int_for_udp() {
        hdr.udp_int.len = hdr.udp.len + ((bit<16>)hdr.int_shim.length * BYTES_PER_SHIM * INT_SHIM_HOP_SIZE) + UDP_HDR_BYTES;
    }

    action insert_udp_int_for_tcp() {
        hdr.udp_int.len = ((bit<16>)hdr.int_shim.length * BYTES_PER_SHIM * INT_SHIM_HOP_SIZE) + TCP_HDR_BYTES + UDP_HDR_BYTES;
    }

    action data_drop(bit<32> device) {
        mark_to_drop(standard_metadata);
        droppedPackets.count(device);
    }

    table data_drop_udp_ipv4_t {
        key = {
            hdr.ethernet.src_mac: exact;
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.udp.dst_port: exact;
        }
        actions = {
            data_drop;
            NoAction;
        }
        size = TABLE_SIZE;
        default_action = NoAction();
    }

    table data_drop_udp_ipv6_t {
        key = {
            hdr.ethernet.src_mac: exact;
            hdr.ipv6.srcAddr: exact;
            hdr.ipv6.dstAddr: exact;
            hdr.udp.dst_port: exact;
        }
        actions = {
            data_drop;
            NoAction;
        }
        size = TABLE_SIZE;
        default_action = NoAction();
    }

    table data_drop_tcp_ipv4_t {
        key = {
            hdr.ethernet.src_mac: exact;
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.tcp.dst_port: exact;
        }
        actions = {
            data_drop;
            NoAction;
        }
        size = TABLE_SIZE;
        default_action = NoAction();
    }

    table data_drop_tcp_ipv6_t {
        key = {
            hdr.ethernet.src_mac: exact;
            hdr.ipv6.srcAddr: exact;
            hdr.ipv6.dstAddr: exact;
            hdr.tcp.dst_port: exact;
        }
        actions = {
            data_drop;
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

     apply {
        if (hdr.udp.isValid()) {
            if (hdr.ipv4.isValid()) {
                data_drop_udp_ipv4_t.apply();
            }
            if (hdr.ipv6.isValid()) {
                data_drop_udp_ipv6_t.apply();
            }
        } else if (hdr.tcp.isValid()) {
            if (hdr.ipv4.isValid()) {
                data_drop_tcp_ipv4_t.apply();
            }
            if (hdr.ipv6.isValid()) {
                data_drop_tcp_ipv6_t.apply();
            }
        }
        if (hdr.arp.isValid()) {
            generate_learn_notification();
            if (hdr.arp.opcode == 1) {
                mac_learn_t.apply();
            }
            else {
                arp_reply_t.apply();
            }
        }
        else if (standard_metadata.egress_spec != DROP_PORT) {
            data_inspection_t.apply();

            if (hdr.int_shim.isValid()) {
                if (hdr.udp.isValid()) {
                    insert_udp_int_for_udp();
                }
                if (hdr.tcp.isValid()) {
                    insert_udp_int_for_tcp();
                }
            }
            data_forward_ipv6_t.apply();
            data_forward_ipv4_t.apply();
        }
    }
}

/*************************************************************************
***********************  S W I T C H  ************************************
*************************************************************************/

V1Switch(
    TpsGwParser(),
    TpsVerifyChecksum(),
    TpsGwIngress(),
    TpsEgress(),
    TpsComputeChecksum(),
    TpsDeparser()
) main;
