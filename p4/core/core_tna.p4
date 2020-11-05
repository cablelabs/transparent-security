/*
# Copyright (c) 2020 Cable Television Laboratories, Inc.
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
/* -*- P4_16 arch -*- */
#include <core.p4>
#include <tna.p4>

/* TPS includes */
#include "../include/tps_consts.p4"
#include "../include/tps_headers.p4"
#include "../include/tna_mirror.p4"
#include "../include/tps_checksum.p4"
#include "../include/tofino_util.p4"

const bit<32> INT_CTR_SIZE = 1;

/*************************************************************************
******************  core_tna TPS P A R S E R  ****************************
*************************************************************************/
parser TpsCoreParser(
    packet_in packet,
    out headers hdr,
    out custom_metadata_t meta,
    out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    state start {
        tofino_parser.apply(packet, ig_intr_md);
        meta.ingress_port = ig_intr_md.ingress_port;
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   ********************
*************************************************************************/

control TpsCoreIngress(
    inout headers hdr,
    inout custom_metadata_t meta,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    /**
    * Responsible for cloning a packet as ingressed
    */
    action mirror_packet_i2e() {
        meta.pkt_type = PKT_TYPE_MIRROR;
        ig_dprsr_md.mirror_type = ING_PORT_MIRROR;

        meta.mirror_header_type = HEADER_TYPE_MIRROR_INGRESS;
        meta.mirror_header_info = (header_info_t)ING_PORT_MIRROR;

        meta.ingress_port   = ig_intr_md.ingress_port;

        /* TODO/FIXME - need to send in this value */
        meta.mirror_session = 1;

        meta.ingress_mac_tstamp    = ig_intr_md.ingress_mac_tstamp;
        meta.ingress_global_tstamp = ig_prsr_md.global_tstamp;
    }

    /**
    * Prepares a packet to be forwarded when data_forward tables have a match
    * on dstAddr
    */
    action data_forward(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }

    table data_forward_t {
        key = {
            hdr.ethernet.dst_mac: exact;
        }
        actions = {
            data_forward;
        }
        size = TABLE_SIZE;
        default_action = data_forward(1);
    }

    apply {
        if (ig_intr_md.resubmit_flag == 0) {
            if (hdr.arp.isValid()) {
                // ARP Request - multicast out to all configured nodes
                if (hdr.arp.opcode == (bit<16>)0x1) {
                    ig_tm_md.mcast_grp_a = (bit<16>)0x1;
                }

                /*
                 * ARP Response to insert mac/port into data_forward_t
                 * send to port 1 containing a switch (aggregate_tna.p4 switch)
                 */
                if (hdr.arp.opcode == (bit<16>)0x2) {
                    ig_dprsr_md.digest_type = DIGEST_TYPE_ARP;
                    data_forward(1);
                }
                // Send to multicast group
            } else if (data_forward_t.apply().hit) {
                if (ig_intr_md.ingress_port == ig_tm_md.ucast_egress_port) {
                    ig_dprsr_md.drop_ctl = 0x1;
                } else {
                    mirror_packet_i2e();
                }
            }
        }
    }
}

/*************************************************************************
***********************  D E P A R S E R  ********************************
*************************************************************************/

control TpsCoreIngressDeparser(
    packet_out packet,
    inout headers hdr,
    in custom_metadata_t meta,
    in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {

    Mirror() ing_port_mirror;
    Digest<digest_t>() arp_digest;

    apply {
        // Block requried for creating the telemtry report
        if (ig_dprsr_md.mirror_type == ING_PORT_MIRROR) {
            ing_port_mirror.emit<mirror_h>(
                meta.mirror_session, {meta.pkt_type});
        }

        // Block required for learning NB routes
        if (ig_dprsr_md.digest_type == DIGEST_TYPE_ARP) {
            arp_digest.pack({
                hdr.arp.src_mac,
                (bit<16>)meta.ingress_port
            });
        }

        /* For Standard and INT Packets */
        packet.emit(hdr);
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   ********************
*************************************************************************/

parser TpsCoreEgressParser(
    packet_in packet,
    out headers hdr,
    out custom_metadata_t meta,
    out egress_intrinsic_metadata_t eg_intr_md) {

    TofinoEgressParser() tofino_parser;

    state start {
        tofino_parser.apply(packet, eg_intr_md);
        mirror_h mirror_md = packet.lookahead<mirror_h>();
        transition select(mirror_md.pkt_type) {
            PKT_TYPE_MIRROR : parse_mirror_md;
            default : parse_normal;
        }
    }

    state parse_normal {
        meta.pkt_type = PKT_TYPE_NORMAL;
        transition parse_ethernet;
    }

    state parse_mirror_md {
        mirror_h mirror_md;
        packet.extract(mirror_md);
        meta.pkt_type = PKT_TYPE_MIRROR;
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            TYPE_IPV6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_UDP: parse_udp_int;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.next_hdr_proto) {
            TYPE_UDP: parse_udp_int;
            default: accept;
        }
    }

    state parse_udp_int {
        packet.extract(hdr.udp_int);
        transition select(hdr.udp_int.dst_port) {
            UDP_INT_DST_PORT: parse_int_shim;
            default: accept;
        }
    }

    state parse_int_shim {
        packet.extract(hdr.int_shim);
        transition parse_int_hdr;
    }

    state parse_int_hdr {
        packet.extract(hdr.int_header);
        transition select(hdr.int_shim.length) {
            0x9: parse_int_meta_3;
            0x8: parse_int_meta_2;
            0x7: parse_int_meta;
            default: accept;
        }
    }

    state parse_int_meta_3 {
        packet.extract(hdr.int_meta_3);
        transition parse_int_meta_2;
    }

    state parse_int_meta_2 {
        packet.extract(hdr.int_meta_2);
        transition parse_int_meta;
    }

    state parse_int_meta {
        packet.extract(hdr.int_meta);
        transition accept;
    }
}

control TpsCoreEgress(
    inout headers hdr,
    inout custom_metadata_t meta,
    in egress_intrinsic_metadata_t eg_intr_md,
    in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
    inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprs,
    inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {

    /**
    * Adds INT data if data_inspection_t table has a match on hdr.ethernet.src_mac
    */
    action add_switch_id(bit<32> switch_id) {
        hdr.int_meta_3.setValid();
        hdr.int_shim.length = hdr.int_shim.length + INT_SHIM_HOP_SIZE;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + BYTES_PER_SHIM;
        hdr.udp_int.len = hdr.udp_int.len + BYTES_PER_SHIM;
        hdr.int_header.remaining_hop_cnt = hdr.int_header.remaining_hop_cnt - 1;
        hdr.int_meta_3.switch_id = switch_id;
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

    action control_drop() {
        eg_intr_md_for_dprs.drop_ctl = 0x1;
    }

    /**
    * Restrutures data within INT packet into a Telemetry Report packet type for ipv4
    */
    action init_telem_rpt() {
        hdr.trpt_eth.setValid();
        hdr.trpt_udp.setValid();
        hdr.trpt_hdr.setValid();

        hdr.trpt_hdr.node_id = hdr.int_meta_3.switch_id;
        hdr.trpt_hdr.rep_type = TRPT_RPT_TYPE_INT_2;
        hdr.trpt_hdr.in_type = TRPT_HDR_IN_TYPE_ETH;
        hdr.trpt_hdr.md_len = hdr.int_shim.length;
        hdr.trpt_hdr.ver = TRPT_VERSION;
        hdr.trpt_hdr.domain_id = TRPT_HDR_DOMAIN_ID;
        hdr.trpt_hdr.sequence_no = 0;
        hdr.trpt_hdr.sequence_pad = 0;
        hdr.trpt_hdr.sequence_no = hdr.trpt_hdr.sequence_no + 1;
        hdr.trpt_eth.dst_mac = hdr.ethernet.dst_mac;
        hdr.trpt_eth.src_mac = hdr.ethernet.src_mac;
        hdr.trpt_udp.dst_port = TRPT_INT_DST_PORT;
    }

    /* Sets the trpt_eth.in_type for IPv4 */
    action set_telem_rpt_in_type_ipv4() {
        // TODO - write tests to test this action
        hdr.trpt_hdr.in_type = TRPT_HDR_IN_TYPE_IPV4;
        hdr.trpt_ipv6.payload_len = hdr.ipv4.totalLen + (
            IPV6_HDR_BYTES + UDP_HDR_BYTES + TRPT_HDR_BASE_BYTES + ETH_HDR_BYTES);
        hdr.trpt_ipv4.totalLen = hdr.ipv4.totalLen + (
            IPV4_HDR_BYTES + UDP_HDR_BYTES + (
                INT_SHIM_BASE_SIZE * BYTES_PER_SHIM) + SWITCH_ID_HDR_BYTES + 6);
        hdr.trpt_udp.len = hdr.ipv4.totalLen + (UDP_HDR_BYTES + (
            INT_SHIM_BASE_SIZE * BYTES_PER_SHIM) + SWITCH_ID_HDR_BYTES + 6);
    }

    /* Sets the trpt_eth.in_type for IPv6 */
    action set_telem_rpt_in_type_ipv6() {
        hdr.trpt_hdr.in_type = TRPT_HDR_IN_TYPE_IPV6;
        hdr.trpt_ipv6.payload_len = hdr.ipv6.payload_len + (
            IPV6_HDR_BYTES + UDP_HDR_BYTES + TRPT_HDR_BASE_BYTES + ETH_HDR_BYTES);
        hdr.trpt_ipv4.totalLen = hdr.ipv6.payload_len + (
            IPV4_HDR_BYTES + UDP_HDR_BYTES + (
                INT_SHIM_BASE_SIZE * BYTES_PER_SHIM) + SWITCH_ID_HDR_BYTES + 6);
        hdr.trpt_udp.len = hdr.ipv6.payload_len + (UDP_HDR_BYTES + (
            INT_SHIM_BASE_SIZE * BYTES_PER_SHIM) + SWITCH_ID_HDR_BYTES + 6);
    }

    /**
    * Restrutures data within INT packet into a Telemetry Report packet type for ipv4
    */
    action setup_telem_rpt_ipv4(ip4Addr_t ae_ip) {
        hdr.trpt_ipv4.setValid();
        hdr.trpt_eth.etherType = TYPE_IPV4;
        hdr.trpt_ipv4.version = 0x4;
        hdr.trpt_ipv4.ihl = 0x5;
        hdr.trpt_ipv4.ttl = DFLT_IPV4_TTL;
        hdr.trpt_ipv4.flags = IPV4_DONT_FRAGMENT;
        hdr.trpt_ipv4.protocol = TYPE_UDP;
        hdr.trpt_ipv4.srcAddr = hdr.ipv4.srcAddr;
        hdr.trpt_ipv4.dstAddr = ae_ip;
    }

    /**
    * Restrutures data within INT packet into a Telemetry Report packet type for ipv4
    */
    action setup_telem_rpt_ipv6(ip6Addr_t ae_ip) {
        hdr.trpt_ipv6.setValid();
        hdr.trpt_eth.etherType = TYPE_IPV6;
        hdr.trpt_ipv6.next_hdr_proto = TYPE_UDP;
        hdr.trpt_ipv6.srcAddr = hdr.ipv6.srcAddr;
        hdr.trpt_ipv6.dstAddr = ae_ip;
    }

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

    /**
    * Removes INT data from a packet
    */
    action clear_int_all() {
        hdr.udp_int.setInvalid();
        hdr.int_shim.setInvalid();
        hdr.int_header.setInvalid();
        hdr.int_meta_2.setInvalid();
        hdr.int_meta_3.setInvalid();
        hdr.int_meta.setInvalid();
    }

    apply {
        if (meta.pkt_type == PKT_TYPE_MIRROR) {
            if (hdr.int_shim.isValid()) {
                add_switch_id_t.apply();
                init_telem_rpt();
                if (hdr.ipv4.isValid()) {
                    set_telem_rpt_in_type_ipv4();
                }
                if (hdr.ipv6.isValid()) {
                    set_telem_rpt_in_type_ipv6();
                }
                setup_telemetry_rpt_t.apply();
                if (hdr.ipv4.isValid()) {
                    hdr.trpt_hdr.rpt_len = hdr.trpt_hdr.rpt_len + 10;
                    hdr.ipv4.protocol = hdr.int_shim.next_proto;
                } else if (hdr.ipv6.isValid()) {
                    hdr.trpt_hdr.rpt_len = hdr.trpt_hdr.rpt_len + 15;
                    hdr.ipv6.next_hdr_proto = hdr.int_shim.next_proto;
                }
                // TODO/FIXME - This may simply be a parameter when configuring the mirror table
                /* Ensure packet is no larger than TRPT_MAX_BYTES
                truncate(TRPT_MAX_BYTES);
                */
            } else {
                control_drop();
            }
        } else {
            if(hdr.int_shim.isValid()) {
                if(hdr.ipv4.isValid()) {
                    hdr.ipv4.protocol = hdr.int_shim.next_proto;
                    if(hdr.udp_int.isValid()) {
                        hdr.ipv4.totalLen = hdr.ipv4.totalLen - (
                            UDP_HDR_BYTES + (
                                INT_SHIM_BASE_SIZE * BYTES_PER_SHIM));
                    } else {
                        hdr.ipv4.totalLen = hdr.ipv4.totalLen - (
                            TCP_HDR_BYTES + (
                                INT_SHIM_BASE_SIZE * BYTES_PER_SHIM));
                    }
                }
                if(hdr.ipv6.isValid()) {
                    hdr.ipv6.next_hdr_proto = hdr.int_shim.next_proto;
                    if(hdr.udp_int.isValid()) {
                        hdr.ipv6.payload_len = hdr.ipv6.payload_len - (
                            UDP_HDR_BYTES + (
                                INT_SHIM_BASE_SIZE * BYTES_PER_SHIM));
                    } else {
                        hdr.ipv6.payload_len = hdr.ipv6.payload_len - (
                            TCP_HDR_BYTES + (
                                INT_SHIM_BASE_SIZE * BYTES_PER_SHIM));
                    }
                }
                clear_int_all();
            }
        }
    }
}

/*************************************************************************
*************************  D E P A R S E R   *****************************
*************************************************************************/

control TpsCoreEgressDeparser(
    packet_out packet,
    inout headers hdr,
    in custom_metadata_t meta,
    in egress_intrinsic_metadata_for_deparser_t eg_intr_dprsr_md) {

    Checksum() checksum;
    apply {
        hdr.ipv4.hdrChecksum = checksum.update(
                {hdr.ipv4.version,
                 hdr.ipv4.ihl,
                 hdr.ipv4.diffserv,
                 hdr.ipv4.totalLen,
                 hdr.ipv4.identification,
                 hdr.ipv4.flags,
                 hdr.ipv4.fragOffset,
                 hdr.ipv4.ttl,
                 hdr.ipv4.protocol,
                 hdr.ipv4.srcAddr,
                 hdr.ipv4.dstAddr});

        hdr.trpt_ipv4.hdrChecksum = checksum.update(
                {hdr.trpt_ipv4.version,
                 hdr.trpt_ipv4.ihl,
                 hdr.trpt_ipv4.diffserv,
                 hdr.trpt_ipv4.totalLen,
                 hdr.trpt_ipv4.identification,
                 hdr.trpt_ipv4.flags,
                 hdr.trpt_ipv4.fragOffset,
                 hdr.trpt_ipv4.ttl,
                 hdr.trpt_ipv4.protocol,
                 hdr.trpt_ipv4.srcAddr,
                 hdr.trpt_ipv4.dstAddr});

        hdr.udp_int.cksum = checksum.update(
                {hdr.udp_int.src_port,
                 hdr.udp_int.dst_port,
                 hdr.udp_int.len});

        hdr.trpt_udp.cksum = checksum.update(
                {hdr.trpt_udp.src_port,
                 hdr.trpt_udp.dst_port,
                 hdr.trpt_udp.len});

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
    }
}

/*************************************************************************
***********************  S W I T C H  ************************************
*************************************************************************/

Pipeline(
    TpsCoreParser(),
    TpsCoreIngress(),
    TpsCoreIngressDeparser(),
    TpsCoreEgressParser(),
    TpsCoreEgress(),
    TpsCoreEgressDeparser()
) pipe;
Switch(pipe) main;
