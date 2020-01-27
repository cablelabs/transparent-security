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
**************  I N G R E S S   P R O C E S S I N G   ********************
*************************************************************************/

control TpsCoreIngress(inout headers hdr,
                       inout metadata meta,
                       inout standard_metadata_t standard_metadata) {

    counter(MAX_DEVICE_ID, CounterType.packets_and_bytes) forwardedPackets;

    action data_forward(macAddr_t dstAddr, egressSpec_t port) {
        hdr.ipv4.protocol = hdr.int_shim.next_proto;
        hdr.int_shim.setInvalid();
        hdr.int_header.setInvalid();
        hdr.int_meta.setInvalid();
        hdr.int_meta_2.setInvalid();

        /*
        TODO - find a better means for resetting the totalLen value after
           invalidating the INT headers which will be problematic when
           implementing header stacks for holding switch_ids */
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - 36;

        standard_metadata.egress_spec = port;
        hdr.ethernet.src_mac = hdr.ethernet.dst_mac;
        hdr.ethernet.dst_mac = dstAddr;
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

    action data_inspect_packet(bit<32> device, bit<32> switch_id) {
        hdr.int_meta.setValid();

        hdr.int_header.remaining_hop_cnt = hdr.int_header.remaining_hop_cnt - 1;

        /* TODO - Find a better means of increasing these sizes using the hdr.int_meta size value */
        hdr.ipv4.totalLen = hdr.ipv4.totalLen + 12;
        hdr.int_shim.length = hdr.int_shim.length + 12;

        hdr.int_meta.switch_id = switch_id;
        hdr.int_meta.orig_mac = hdr.ethernet.src_mac;

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

     apply {
        if (hdr.ipv4.isValid()) {
            data_inspection_t.apply();
            data_clone_t.apply();
            data_forward_t.apply();
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
    TpsEgress(),
    TpsComputeChecksum(),
    TpsDeparser()
) main;
