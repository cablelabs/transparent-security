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

const bit<32> INT_CTR_IDX = 1;


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   ********************
*************************************************************************/

control TpsCoreIngress(inout headers hdr,
                       inout metadata meta,
                       inout standard_metadata_t standard_metadata) {

    /**
    * Responsible for recirculating a packet after egress processing
    */
    action recirculate_packet() {
        recirculate(standard_metadata);
    }

    /**
    * Responsible for cloning a packet as ingressed
    */
    action clone_packet_i2e() {
        clone3(CloneType.I2E, I2E_CLONE_SESSION_ID, standard_metadata);
    }

    /**
    * Adds INT data if data_inspection_t table has a match on hdr.ethernet.src_mac
    */
    action data_inspect_packet(bit<32> switch_id) {
        hdr.int_meta_3.setValid();
        hdr.int_shim.length = hdr.int_shim.length + INT_SHIM_HOP_SIZE;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + (INT_SHIM_HOP_SIZE * BYTES_PER_SHIM);
        hdr.udp_int.len = hdr.udp_int.len + (INT_SHIM_HOP_SIZE * BYTES_PER_SHIM);
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
        size = TABLE_SIZE;
        default_action = NoAction();
    }

    /**
    * Prepares a packet to be forwarded when data_forward tables have a match on dstAddr
    */
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

    /**
    * Removes INT data from a packet
    */
    action clear_int() {
        hdr.ipv4.protocol = hdr.int_shim.next_proto;
        hdr.ipv6.next_hdr_proto = hdr.int_shim.next_proto;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - ((bit<16>)hdr.int_shim.length * BYTES_PER_SHIM * INT_SHIM_HOP_SIZE);
        hdr.ipv6.payload_len = hdr.ipv6.payload_len - ((bit<16>)hdr.int_shim.length * BYTES_PER_SHIM * INT_SHIM_HOP_SIZE);

        hdr.udp_int.setInvalid();
        hdr.int_shim.setInvalid();
        hdr.int_header.setInvalid();
        hdr.int_meta_2.setInvalid();
        hdr.int_meta_3.setInvalid();
        hdr.int_meta.setInvalid();
    }

    apply {
        if (standard_metadata.egress_spec != DROP_PORT) {
            if (IS_NORMAL(standard_metadata)) {
                data_inspection_t.apply();
                recirculate_packet();
            } else if (IS_RECIRCULATED(standard_metadata)) {
                if (hdr.ipv4.isValid()) {
                    data_forward_ipv4_t.apply();
                } else if (hdr.ipv6.isValid()) {
                    data_forward_ipv6_t.apply();
                }
                if (hdr.int_shim.isValid()) {
                    clone_packet_i2e();
                    clear_int();
                }
            }
        }
    }
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   ********************
*************************************************************************/

control TpsCoreEgress(inout headers hdr,
                      inout metadata meta,
                      inout standard_metadata_t standard_metadata) {

    register<bit<22>>(INT_CTR_IDX) trpt_pkts;

    action control_drop() {
        mark_to_drop(standard_metadata);;
    }

    /**
    * Restrutures data within INT packet into a Telemetry Report packet type for ipv4
    */
    action init_telem_rpt() {
        hdr.trpt_eth.setValid();
        hdr.trpt_udp.setValid();
        hdr.trpt_hdr.setValid();

        hdr.trpt_eth.dst_mac = hdr.ethernet.dst_mac;
        hdr.trpt_eth.src_mac = hdr.ethernet.src_mac;

        hdr.trpt_udp.dst_port = TRPT_INT_DST_PORT;

        hdr.trpt_hdr.ver = TRPT_VERSION;
        hdr.trpt_hdr.domain_id = TRPT_HDR_DOMAIN_ID;
        hdr.trpt_hdr.length = hdr.trpt_hdr.length + hdr.int_shim.length + 5; /* 5 Reflects TRPT ethernet & udp packets

        /* TODO - determine if counter resets to 0 once it reaches max */
        trpt_pkts.read(hdr.trpt_hdr.sequence_no, 32w0x0);
        hdr.trpt_hdr.sequence_no = hdr.trpt_hdr.sequence_no + 1;
        trpt_pkts.write(32w0x0, hdr.trpt_hdr.sequence_no);
    }

    /**
    * Restrutures data within INT packet into a Telemetry Report packet type for ipv4
    */
    action setup_telem_rpt_ipv4(ip4Addr_t ae_ip) {
        hdr.trpt_ipv4.setValid();

        hdr.trpt_hdr.length = hdr.trpt_hdr.length + 5;  /* Reflects the IPv4 header bytes */
        hdr.trpt_eth.etherType = TYPE_IPV4;

        hdr.trpt_ipv4.version = 0x4;
        hdr.trpt_ipv4.ihl = 0x5;
        hdr.trpt_ipv4.totalLen = (bit<16>)standard_metadata.packet_length + IPV4_HDR_BYTES + UDP_HDR_BYTES + TRPT_HDR_BASE_BYTES;
        hdr.trpt_ipv4.ttl = DFLT_IPV4_TTL;
        hdr.trpt_ipv4.flags = IPV4_DONT_FRAGMENT;
        hdr.trpt_ipv4.protocol = TYPE_UDP;
        hdr.trpt_ipv4.srcAddr = hdr.ipv4.srcAddr;
        hdr.trpt_ipv4.dstAddr = ae_ip;

        hdr.trpt_udp.len = hdr.trpt_ipv4.totalLen - IPV4_HDR_BYTES;
    }

    /**
    * Restrutures data within INT packet into a Telemetry Report packet type for ipv4
    */
    action setup_telem_rpt_ipv6(ip6Addr_t ae_ip) {
        hdr.trpt_ipv6.setValid();
        hdr.trpt_hdr.length = hdr.trpt_hdr.length + 10; /* Reflects the IPv6 header bytes */
        hdr.trpt_eth.etherType = TYPE_IPV6;
        hdr.trpt_ipv6.next_hdr_proto = TYPE_UDP;
        hdr.trpt_ipv6.srcAddr = hdr.ipv6.srcAddr;
        hdr.trpt_ipv6.dstAddr = ae_ip;
    }

    /* TODO - Design table properly, currently just making IPv4 or IPv6 Choices */
    table setup_telemetry_rpt_t {
        key = {
            hdr.udp_int.dst_port: exact;
        }
        actions = {
            setup_telem_rpt_ipv4;
            setup_telem_rpt_ipv6;
            control_drop;
        }
        size = TABLE_SIZE;
        default_action = control_drop();
    }

    apply {
        if (standard_metadata.egress_spec != DROP_PORT) {
            if (IS_I2E_CLONE(standard_metadata)) {
                init_telem_rpt();
                setup_telemetry_rpt_t.apply();
            }
        }
    }
}


/*************************************************************************
***********************  S W I T C H  ************************************
*************************************************************************/

V1Switch(
    TpsCoreParser(),
    TpsVerifyChecksum(),
    TpsCoreIngress(),
    TpsCoreEgress(),
    TpsComputeChecksum(),
    TpsDeparser()
) main;
