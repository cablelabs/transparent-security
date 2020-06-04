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
#ifdef TOFINO
#include <tofino.p4>
#endif

#include <core.p4>
#include <v1model.p4>

/* TPS includes */
#include <tps_headers.p4>
#include <tps_parser.p4>
#include <tps_checksum.p4>
#include <tps_egress.p4>

const bit<32> INT_CTR_SIZE = 1;


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
        #ifdef TOFINO
        resubmit(standard_metadata);
        #endif
        #ifdef BMV2
        recirculate(standard_metadata);
        #endif
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

    action arp_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
    }

    table arp_forward_t {
        key = {
            hdr.ethernet.dst_mac: exact;
        }
        actions = {
            arp_forward;
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
            }
            else if (hdr.arp.opcode == 2) {
                arp_forward_t.apply();
            }
        } else if (standard_metadata.egress_spec != DROP_PORT) {
            if (IS_NORMAL(standard_metadata)) {
                data_inspection_t.apply();
                recirculate_packet();
            } else if (IS_RECIRCULATED(standard_metadata)) {
                data_forward_t.apply();
                if (hdr.int_shim.isValid()) {
                    clone_packet_i2e();

                    # TODO/FIXME - error "In the ALU operation over container B7 in action TpsCoreIngress.clear_int, every write bit does not have a corresponding 1 or 0 read bits."
                    #ifdef BMV2
                    clear_int();
                    #endif
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

    #ifdef BMV2
    register<bit<16>>(INT_CTR_SIZE) trpt_pkts;
    #endif

    action control_drop() {
        mark_to_drop(standard_metadata);
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
        if (hdr.arp.isValid()) {
            if(IS_REPLICATED(standard_metadata)) {
                if (standard_metadata.egress_port == standard_metadata.ingress_port) {
                    control_drop();
                }
            }
        } else if (standard_metadata.egress_spec != DROP_PORT) {
            if (IS_I2E_CLONE(standard_metadata)) {
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
                #ifdef BMV2
                truncate(TRPT_MAX_BYTES);
                #endif
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
