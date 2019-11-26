/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_INSPECTION = 0x1212;
const bit<8> TYPE_UDP = 0x11;
const bit<16> TYPE_IPV4 = 0x800;
const bit<32> MAX_DEVICE_ID = 15;
const bit<9> DROP_PORT = 511;

#define MAX_HOPS 9


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
    bit<16> cksum;
}

header inspection_t {
    macAddr_t srcAddr;
    ip4Addr_t deviceAddr;
    ip4Addr_t dstAddr;
    bit<16>   dstPort;
    bit<16> proto_id;
}

struct fwd_meta_t {
    bit<32> l2ptr;
    bit<24> out_bd;
}

struct metadata {
    fwd_meta_t fwd;
}

struct headers {
    ethernet_t   ethernet;
    inspection_t inspection;
    ipv4_t       ipv4;
    udp_t        udp;
}


control debug_meta(in metadata meta, in headers hdr)
{
    table dbg_table {
        key = {
           hdr.inspection.srcAddr: exact;
           hdr.inspection.deviceAddr: exact;
           hdr.inspection.dstAddr: exact;
           hdr.inspection.dstPort: exact;
           hdr.inspection.proto_id: exact;
           hdr.ipv4.srcAddr: exact;
           hdr.ipv4.dstAddr: exact;
           hdr.udp.dst_port: exact;
           hdr.ethernet.dstAddr: exact;
           hdr.ethernet.srcAddr: exact;
           hdr.ipv4.identification: exact;
        }
        actions = { NoAction; }
        const default_action = NoAction();
    }
    apply {
        dbg_table.apply();
    }
}

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

    debug_meta() debug_meta_ingress_start;
    debug_meta() debug_meta_ingress_end;

    counter(MAX_DEVICE_ID, CounterType.packets_and_bytes) forwardedPackets;
    counter(MAX_DEVICE_ID, CounterType.packets_and_bytes) droppedPackets;

    action data_forward(macAddr_t dstAddr, egressSpec_t port, bit<32> l2ptr) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        meta.fwd.l2ptr = l2ptr;
    }

    table data_forward_t {
        key = {
            standard_metadata.ingress_port: exact;
        }
        actions = {
            data_forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action data_inspect_packet(bit<32> device) {
        hdr.inspection.setValid();
        hdr.inspection.srcAddr = hdr.ethernet.srcAddr;
        hdr.inspection.deviceAddr = hdr.ipv4.srcAddr;
        hdr.inspection.dstAddr  = hdr.ipv4.dstAddr;
        hdr.inspection.dstPort = hdr.udp.dst_port;
        hdr.inspection.proto_id = TYPE_IPV4;
        hdr.ethernet.etherType = TYPE_INSPECTION;
        forwardedPackets.count(device);
    }

    table data_inspection_t {
        key = {
            hdr.ethernet.srcAddr: exact;
        }
        actions = {
            data_inspect_packet;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action data_drop(bit<32> device) {
        mark_to_drop(standard_metadata);;
        droppedPackets.count(device);
    }

    table data_drop_t {
        key = {
            hdr.ipv4.dstAddr: exact;
            hdr.udp.dst_port: exact;
            hdr.udp.len: exact;
        }
        actions = {
            data_drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action control_drop() {
        mark_to_drop(standard_metadata);;
    }

    action control_forward(macAddr_t mac, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = mac;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
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

     apply {
        if (hdr.ipv4.isValid()) {
            if (hdr.udp.isValid()) {
                data_drop_t.apply();
                if (standard_metadata.egress_spec != DROP_PORT) {
                    data_inspection_t.apply();
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
        debug_meta() debug_meta_engress_start;

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
