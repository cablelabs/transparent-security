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

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
typedef PortId_t egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<128> ip6Addr_t;

/*************************
Ethernet header definition
**************************/
header ethernet_t {
    macAddr_t dst_mac;
    macAddr_t src_mac;
    bit<16>   etherType;
}

/*************************
ARP header definition
**************************/
header arp_t {
    bit<16>    hwType;
    bit<16>    protoType;
    bit<8>     hwAddrLen;
    bit<8>     protoAddrLen;
    bit<16>    opcode;
    bit<48>    src_mac;
    bit<32>    srcAddr;
    bit<48>    dst_mac;
    bit<32>    dstAddr;
}
/*************************
IPv4 header definition
**************************/
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

/*************************
IPv6 header definition
**************************/
header ipv6_t {
    bit<4>    version;
    bit<8>    class;
    bit<20>   flow_label;
    bit<16>   payload_len;
    bit<8>    next_hdr_proto;
    bit<8>    hop_limit;
    ip6Addr_t srcAddr;
    ip6Addr_t dstAddr;
}

/*************************
UDP header definition
**************************/
header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
    bit<16> cksum;
}

/*************************
TCP header definition
**************************/
header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

/******************************************
External Gateway INT Data header definition
*******************************************/
header int_udp_shim_t { /* 4 */
    bit<4>  type;
    bit<2>  npt;
    bit<2>  res1;
    bit<8>  length;
    bit<8>  res2;
    bit<8>  next_proto;
}

header int_header_t { /* 12 */
    bit<4>  ver;
    bit<2>  res;
    bit<1>  d;
    bit<1>  e;
    bit<1>  m;
    bit<10> reserved;
    bit<5>  meta_len;
    bit<8>  remaining_hop_cnt;
    bit<1> instr_bit_0;
    bit<15> instr_bit_bal;
    bit<16> domain_id;
    bit<1> ds_instr_0;
    bit<15> ds_instr_bal;
    bit<1>  ds_flags_0;
    bit<1>  ds_flags_1;
    bit<14> ds_flags_bal;
}

header source_metadata_t { /* 12 */
    bit<32>  switch_id;
    bit<48>  orig_mac;
    bit<16>  reserved;
}

header int_metadata_t { /* 4 */
    bit<32>  switch_id;
}

header telem_rpt_t { /* 10 */
    bit<4>  ver;
    bit<6>  hw_id;
    bit<16> sequence_no;
    bit<6> sequence_pad;
    bit<32> node_id;
    bit<4> rep_type;
    bit<4> in_type;
    bit<8> rpt_len;
    bit<8> md_len;
    bit<1> d;
    bit<1> q;
    bit<1> f;
    bit<1> i;
    bit<4> reserved;
    bit<1>  rep_md_bit0; /* Contains Ingress & Egress port IDs */
    bit<1>  rep_md_bit1;
    bit<1>  rep_md_bit2;
    bit<1>  rep_md_bit3;
    bit<1>  rep_md_bit4;
    bit<1>  rep_md_bit5;
    bit<1>  rep_md_bit6;
    bit<1>  rep_md_bit7;
    bit<1>  rep_md_bit8;
    bit<1>  rep_md_bit9;
    bit<1>  rep_md_bit10;
    bit<1>  rep_md_bit11;
    bit<1>  rep_md_bit12;
    bit<1>  rep_md_bit13;
    bit<1>  rep_md_bit14;
    bit<1>  rep_md_bit15;
    bit<16> domain_id;
    bit<1>  ds_mdb_bit0;
    bit<1>  ds_mdb_bit1;
    bit<1>  ds_mdb_bit2;
    bit<1>  ds_mdb_bit3;
    bit<1>  ds_mdb_bit4;
    bit<1>  ds_mdb_bit5;
    bit<1>  ds_mdb_bit6;
    bit<1>  ds_mdb_bit7;
    bit<1>  ds_mdb_bit8;
    bit<1>  ds_mdb_bit9;
    bit<1>  ds_mdb_bit10;
    bit<1>  ds_mdb_bit11;
    bit<1>  ds_mdb_bit12;
    bit<1>  ds_mdb_bit13;
    bit<1>  ds_mdb_bit14;
    bit<1>  ds_mdb_bit15;
    bit<1>  ds_mds_bit0;
    bit<1>  ds_mds_bit1;
    bit<1>  ds_mds_bit2;
    bit<1>  ds_mds_bit3;
    bit<1>  ds_mds_bit4;
    bit<1>  ds_mds_bit5;
    bit<1>  ds_mds_bit6;
    bit<1>  ds_mds_bit7;
    bit<1>  ds_mds_bit8;
    bit<1>  ds_mds_bit9;
    bit<1>  ds_mds_bit10;
    bit<1>  ds_mds_bit11;
    bit<1>  ds_mds_bit12;
    bit<1>  ds_mds_bit13;
    bit<1>  ds_mds_bit14;
    bit<1>  ds_mds_bit15;
    bit<32> var_opt_md;
}

header bridge_md_t {
    bit<16>  pkt_type;
}

struct headers {
    bridge_md_t       bridge_md;
    ethernet_t        trpt_eth;
    ipv4_t            trpt_ipv4;
    ipv6_t            trpt_ipv6;
    udp_t             trpt_udp;
    telem_rpt_t       trpt_hdr;

    ethernet_t        ethernet;
    ipv4_t            ipv4;
    ipv6_t            ipv6;
    udp_t             udp_int;
    int_udp_shim_t    int_shim;
    int_header_t      int_header;
    int_metadata_t    int_meta_3;
    int_metadata_t    int_meta_2;
    source_metadata_t int_meta;

    arp_t             arp;
    udp_t             udp;
    tcp_t             tcp;
}

struct mac_learn_digest {
    bit<48> src_mac;
    PortId_t ingress_port;
}

struct nat_digest {
   bit<16> udp_src_port;
   bit<16> tcp_src_port;
   bit<32> local_ip;
}

struct metadata {
    ip4Addr_t ipv4_addr;
    ip6Addr_t ipv6_addr;
    bit<16>   dst_port;
    macAddr_t src_mac;
    macAddr_t dst_mac;
    PortId_t  ingress_port;
}

struct digest_t {
    macAddr_t src_mac;
    bit<16>  port;
}
