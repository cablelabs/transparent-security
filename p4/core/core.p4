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

    action data_forward(macAddr_t dstAddr, egressSpec_t port) {
        /*
        TODO/FIXME - data_inspection should be forwarding to port 3 but is
            not so I added this line in
        */
        clone3(CloneType.I2E, I2E_CLONE_SESSION_ID, standard_metadata);

        hdr.ipv4.protocol = hdr.int_shim.next_proto;
        hdr.ipv4.totalLen = hdr.ipv4.totalLen - ((bit<16>)hdr.int_shim.length * 4);
        hdr.int_shim.setInvalid();
        hdr.int_header.setInvalid();
        hdr.int_meta.setInvalid();
        hdr.int_meta_2.setInvalid();
        hdr.int_meta_3.setInvalid();

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

    action data_inspect_packet(bit<32> switch_id, egressSpec_t egress_port) {
        hdr.int_meta_3.setValid();

        hdr.ipv4.totalLen = hdr.ipv4.totalLen + ((bit<16>)hdr.int_header.meta_len * 4);
        hdr.int_shim.length = hdr.int_shim.length + (bit<8>)hdr.int_header.meta_len;
        hdr.int_header.remaining_hop_cnt = hdr.int_header.remaining_hop_cnt - 1;

        hdr.int_meta_3.switch_id = hdr.int_meta_2.switch_id;
        hdr.int_meta_3.orig_mac = hdr.int_meta_2.orig_mac;
        hdr.int_meta_2.switch_id = hdr.int_meta.switch_id;
        hdr.int_meta_2.orig_mac = hdr.int_meta.orig_mac;
        hdr.int_meta.switch_id = switch_id;
        hdr.int_meta.orig_mac = 0xFFFFFFFFFFFF;

        /* TODO - this action is not resulting with the INT packet being
             egressed to the configured port (3 in this use case), therefore
             I added clone3() to data_forward() to ensure the AE is receiving
             the required packets */
        standard_metadata.egress_spec = egress_port;

        recirculate<standard_metadata_t>(standard_metadata);
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

     apply {
        if (hdr.ipv4.isValid()) {
            if (standard_metadata.instance_type == 0) {
                data_inspection_t.apply();
            } else {
                data_forward_t.apply();
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
    TpsEgress(),
    TpsComputeChecksum(),
    TpsDeparser()
) main;
