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
#include <tna.p4>

/* TPS includes */
#include "../include/tps_consts.p4"
#include "../include/tps_headers.p4"
#include "../include/tps_checksum.p4"

const bit<32> INT_CTR_SIZE = 1;

/*************************************************************************
******************** Core TPS P A R S E R  *******************************
*************************************************************************/
parser TpsCoreParser(packet_in packet,
                     out headers hdr,
                     out metadata meta,
                     out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP: parse_arp;
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
        transition select (hdr.int_shim.next_proto) {
            TYPE_UDP: parse_udp;
            TYPE_TCP: parse_tcp;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

}

// Empty egress parser/control blocks
parser EmptyEgressParser(
        packet_in pkt,
        out headers hdr,
        out metadata eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        transition accept;
    }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   ********************
*************************************************************************/

control TpsCoreIngress1(inout headers hdr,
                        inout metadata meta,
                        in ingress_intrinsic_metadata_t ig_intr_md,
                        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

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
    action recirculate_to_pipe2() {
    /* TODO/FIXME
        eg_intr_md.egress_port = ig_intr_md.ingress_port;
    */
    }

    apply {
        if (ig_intr_md.ingress_port != DROP_PORT) {
                data_inspection_t.apply();
                recirculate_to_pipe2();
        }
    }
}

control TpsCoreIngress2(inout headers hdr,
                        inout metadata meta,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    /**
    * Responsible for cloning a packet as ingressed
    */
    action clone_packet_i2e() {
        // TODO/FIXME - need to find tna equivalent
        /*clone3(CloneType.I2E, I2E_CLONE_SESSION_ID, standard_metadata);*/
    }

    /**
    * Prepares a packet to be forwarded when data_forward tables have a match on dstAddr
    */
    action data_forward(egressSpec_t port) {
    /* TODO/FIMXE
        eg_intr_md.egress_port = port;
    */
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

    /**
    * Removes INT data from a packet
    */
    action clear_int() {
        hdr.ipv4.protocol = hdr.int_shim.next_proto;
        hdr.ipv6.next_hdr_proto = hdr.int_shim.next_proto;

        // TODO/FIXME - so this works for both BMV2 & TOFINO
        #ifdef BMV2
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - ((bit<16>)hdr.int_shim.length * BYTES_PER_SHIM * INT_SHIM_HOP_SIZE);
        hdr.ipv6.payload_len = hdr.ipv6.payload_len - ((bit<16>)hdr.int_shim.length * BYTES_PER_SHIM * INT_SHIM_HOP_SIZE);
        #endif

        hdr.udp_int.setInvalid();
        hdr.int_shim.setInvalid();
        hdr.int_header.setInvalid();
        hdr.int_meta_2.setInvalid();
        hdr.int_meta_3.setInvalid();
        hdr.int_meta.setInvalid();
    }

    apply {
        if (ig_intr_md.ingress_port != DROP_PORT) {
            data_forward_t.apply();
            if (hdr.int_shim.isValid()) {
                clone_packet_i2e();
            /* TODO/FIXME
                clear_int();
            */
            }
        }
    }
}


/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   ********************
*************************************************************************/

control EmptyEgress(inout headers hdr,
                    inout metadata meta,
                    in egress_intrinsic_metadata_t eg_intr_md,
                    in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
                    inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprs,
                    inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {
    apply {
    }
}

control TpsCoreEgress(inout headers hdr,
                      inout metadata meta,
                      in egress_intrinsic_metadata_t eg_intr_md,
                      in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
                      inout egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprs,
                      inout egress_intrinsic_metadata_for_output_port_t eg_intr_md_for_oport) {
    action control_drop() {
    /* TODO - determine proper way to do this on Tofino
        eg_intr_md.egress_port = 0;
    */
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

        hdr.trpt_eth.dst_mac = hdr.ethernet.dst_mac;
        hdr.trpt_eth.src_mac = hdr.ethernet.src_mac;

        hdr.trpt_udp.dst_port = TRPT_INT_DST_PORT;

        hdr.trpt_hdr.ver = TRPT_VERSION;
        hdr.trpt_hdr.domain_id = TRPT_HDR_DOMAIN_ID;

        hdr.trpt_hdr.sequence_no = 0;
        hdr.trpt_hdr.sequence_pad = 0;

        // TODO/FIXME - so this works for both BMV2 & TOFINO
        #ifdef BMV2
        hdr.trpt_hdr.rpt_len = hdr.trpt_hdr.rpt_len + hdr.int_shim.length + 5; /* 5 Reflects TRPT ethernet & udp packets

        /* TODO - determine if counter resets to 0 once it reaches max */
        trpt_pkts.read(hdr.trpt_hdr.sequence_no, INT_CTR_SIZE - 1);
        hdr.trpt_hdr.sequence_no = hdr.trpt_hdr.sequence_no + 1;
        //trpt_pkts.write(INT_CTR_SIZE - 1, hdr.trpt_hdr.sequence_no);
        #endif
    }

    /* Sets the trpt_eth.in_type for IPv4 */
    action set_telem_rpt_in_type_ipv4() {
        hdr.trpt_hdr.in_type = TRPT_HDR_IN_TYPE_IPV4;
    }

    /* Sets the trpt_eth.in_type for IPv6 */
    action set_telem_rpt_in_type_ipv6() {
        hdr.trpt_hdr.in_type = TRPT_HDR_IN_TYPE_IPV6;
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

        // TODO/FIXME - so this works for both BMV2 & TOFINO
        #ifdef BMV2
        hdr.trpt_udp.len = hdr.trpt_ipv4.totalLen - IPV4_HDR_BYTES;
        hdr.trpt_ipv4.totalLen = (bit<16>)standard_metadata.packet_length + IPV4_HDR_BYTES + UDP_HDR_BYTES + TRPT_HDR_BASE_BYTES;
        #endif
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

    /**
    * Updates the TRPT header length value when the underlying packet is IPv4
    */
    action update_trpt_hdr_len_ipv4() {
        hdr.trpt_hdr.rpt_len = hdr.trpt_hdr.rpt_len + 5;
    }

    /**
    * Updates the TRPT header length value when the underlying packet is IPv6
    */
    action update_trpt_hdr_len_ipv6() {
        hdr.trpt_hdr.rpt_len = hdr.trpt_hdr.rpt_len + 10;
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
    /* TODO/FIXME
        if (ig_intr_md.ingress_port != DROP_PORT) {
            if (ig_intr_md.resubmit_flag != 0) {
    */
                init_telem_rpt();
                if (hdr.ipv4.isValid()) {
                    set_telem_rpt_in_type_ipv4();
                }
                if (hdr.ipv6.isValid()) {
                    set_telem_rpt_in_type_ipv6();
                }
                setup_telemetry_rpt_t.apply();
                if (hdr.ipv4.isValid()) {
                    update_trpt_hdr_len_ipv4();
                } else if (hdr.ipv6.isValid()) {
                    update_trpt_hdr_len_ipv6();
                }
                /* Ensure packet is no larger than TRPT_MAX_BYTES */
                /* TODO/FIND equivalent
                truncate(TRPT_MAX_BYTES);
                */
            }
    /*
        }
    }
    */
}


/*************************************************************************
***********************  D E P A R S E R  ********************************
*************************************************************************/

control TpsCoreIngressDeparser(packet_out packet,
                        inout headers hdr,
                        in metadata meta,
                        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
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

control TpsCoreEgressDeparser(packet_out packet,
                        inout headers hdr,
                        in metadata meta,
                        in egress_intrinsic_metadata_for_deparser_t eg_intr_dprsr_md) {
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


/*************************************************************************
***********************  S W I T C H  ************************************
*************************************************************************/
Pipeline(
    TpsCoreParser(),
    TpsCoreIngress1(),
    TpsCoreIngressDeparser(),
    EmptyEgressParser(),
    EmptyEgress(),
    TpsCoreEgressDeparser()
) pipe1;

Pipeline(
    TpsCoreParser(),
    TpsCoreIngress2(),
    TpsCoreIngressDeparser(),
    EmptyEgressParser(),
    TpsCoreEgress(),
    TpsCoreEgressDeparser()
) pipe2;

Switch(pipe1, pipe2) main;