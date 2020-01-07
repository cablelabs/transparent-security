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
#include <tps_headers.p4>

const bit<16> TYPE_INSPECTION = 0x1212;
const bit<8> TYPE_UDP = 0x11;
const bit<16> TYPE_IPV4 = 0x800;
const bit<32> MAX_DEVICE_ID = 15;
const bit<9> DROP_PORT = 511;

#define MAX_HOPS 9
#define BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE 1
#define IS_I2E_CLONE(std_meta) (std_meta.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_INGRESS_CLONE)
#define IOAM_CLONE_SPEC 0x1000

const bit<32> I2E_CLONE_SESSION_ID = 5;

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_INSPECTION: parse_inspection;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_inspection {
        packet.extract(hdr.inspection);
        transition select(hdr.inspection.proto_id) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            TYPE_UDP : parse_udp;
            default: accept;
        }
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dst_port) {
            default: accept;
        }
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {


    counter(MAX_DEVICE_ID, CounterType.packets_and_bytes) droppedPackets;

    action data_forward(macAddr_t dstAddr, egressSpec_t port) {
        hdr.inspection.setInvalid();
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.srcAddr = hdr.inspection.deviceAddr;
        hdr.ipv4.dstAddr = hdr.inspection.dstAddr;
        hdr.udp.dst_port = hdr.inspection.dstPort;
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
            hdr.inspection.srcAddr: exact;
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
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = mac;
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
            hdr.inspection.srcAddr: exact;
            hdr.inspection.deviceAddr: exact;
            hdr.inspection.dstAddr: exact;
            hdr.inspection.dstPort: exact;
            hdr.inspection.proto_id: exact;
            hdr.ipv4.srcAddr: exact;
            hdr.ipv4.dstAddr: exact;
            hdr.udp.dst_port: exact;
            hdr.ethernet.dstAddr: exact;
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
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply {

     }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.inspection);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
