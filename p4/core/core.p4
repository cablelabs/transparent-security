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

const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_NORMAL        = 0;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE = 1;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE  = 2;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_COALESCED     = 3;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RECIRC        = 4;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_REPLICATION   = 5;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_RESUBMIT      = 6;

#define IS_NORMAL(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_NORMAL)
#define IS_RESUBMITTED(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_RESUBMIT)
#define IS_RECIRCULATED(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_RECIRC)
#define IS_I2E_CLONE(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE)
#define IS_E2E_CLONE(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE)
#define IS_REPLICATED(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_REPLICATION)

/*#define IOAM_CLONE_SPEC 0x1000*/
const bit<32> I2E_CLONE_SESSION_ID = 5;
const bit<32> E2E_CLONE_SESSION_ID = 11;


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
    * Responsible for cloning a packet as egressed
    */
    action clone_packet_e2e() {
        clone3(CloneType.E2E, E2E_CLONE_SESSION_ID, standard_metadata);
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
            } else if (IS_RESUBMITTED(standard_metadata) || IS_RECIRCULATED(standard_metadata)) {
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

    /**
    * Restrutures data within INT packet into a Telemetry Report packet type
    */
    action setup_telem_rpt() {
        /* TODO - Implement me */
        /*hdr.int_shim.setInvalid();*/
    }

    table debug_meta {
        key = {
           standard_metadata.instance_type: exact;
        }
        actions = {
            NoAction;
        }
        const default_action = NoAction();
    }

    table debug_int {
        key = {
           hdr.udp_int.dst_port: exact;
           hdr.int_shim.next_proto: exact;
           hdr.udp_int.dst_port: exact;
           hdr.int_header.meta_len: exact;
           hdr.int_meta.orig_mac: exact;
        }
        actions = {
            NoAction;
        }
        const default_action = NoAction();
    }

    apply {
        debug_meta.apply();
        if (hdr.int_shim.isValid()) {
            debug_int.apply();
        }

        if (standard_metadata.egress_spec != DROP_PORT) {
            if (IS_E2E_CLONE(standard_metadata) || IS_I2E_CLONE(standard_metadata)) {
                setup_telem_rpt();
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
