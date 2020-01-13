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

#define BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE 1
#define IS_I2E_CLONE(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE)
#define IOAM_CLONE_SPEC 0x1000

const bit<32> I2E_CLONE_SESSION_ID = 5;

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control TpsCoreIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {


    counter(MAX_DEVICE_ID, CounterType.packets_and_bytes) droppedPackets;

    action data_forward(macAddr_t dstAddr, egressSpec_t port) {
        hdr.gw_int_header.setInvalid();
        hdr.gw_int.setInvalid();
        hdr.sw_int_header.setInvalid();
        hdr.sw_int.setInvalid();
        standard_metadata.egress_spec = port;
        hdr.ethernet.src_mac = hdr.ethernet.dst_mac;
        hdr.ethernet.dst_mac = dstAddr;
        hdr.ethernet.etherType = TYPE_IPV4;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    table data_forward_t {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            data_forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action data_drop(bit<32> device) {
        mark_to_drop(standard_metadata);
        droppedPackets.count(device);
    }

    table data_drop_t {
        key = {
            hdr.gw_int.src_mac: exact;
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.udp.dst_port: exact;
        }
        actions = {
            data_drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action data_clone() {
        clone3(CloneType.I2E, I2E_CLONE_SESSION_ID, standard_metadata);
    }

    table data_clone_t {
        actions = {
            data_clone;
            NoAction;
        }
        default_action = data_clone;
    }

    action control_forward(macAddr_t mac, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.src_mac = hdr.ethernet.dst_mac;
        hdr.ethernet.dst_mac = mac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action control_drop() {
        mark_to_drop(standard_metadata);
    }

    table control_forward_t {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            control_forward;
            control_drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table dbg_table {
        key = {
            standard_metadata.ingress_port : exact;
            standard_metadata.egress_spec : exact;
            standard_metadata.egress_port : exact;
            standard_metadata.instance_type : exact;
            standard_metadata.ingress_global_timestamp : exact;
            standard_metadata.mcast_grp : exact;
            standard_metadata.checksum_error : exact;
            hdr.gw_int.src_mac: exact;
            hdr.gw_int.proto_id: exact;
            hdr.sw_int.switch_id: exact;
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.udp.dst_port: exact;
            hdr.ethernet.dst_mac: exact;
            hdr.ipv4.identification: exact;
        }
        actions = { NoAction; }
        const default_action = NoAction();
    }

     apply {
        if (hdr.ipv4.isValid()) {
            dbg_table.apply();
            if (hdr.udp.isValid()) {
                 data_drop_t.apply();
                 if (standard_metadata.egress_spec != DROP_PORT) {
                     data_clone_t.apply();
                     data_forward_t.apply();
                 }
            }
            else {
                control_forward_t.apply();
            }
        }

    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
    TpsParser(),
    TpsVerifyChecksum(),
    TpsCoreIngress(),
    TpsEgress(),
    TpsComputeChecksum(),
    TpsDeparser()
) main;
