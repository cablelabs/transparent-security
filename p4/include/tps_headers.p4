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
typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/*************************
Ethernet header definition
**************************/
header ethernet_t {
    macAddr_t dst_mac;
    macAddr_t src_mac;
    bit<16>   etherType;
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
UDP header definition
**************************/
header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
    bit<16> cksum;
}

/******************************************
External Gateway INT Data header definition
*******************************************/
header int_ip_shim_t { /* 4 */
    bit<8>  type;
    bit<8>  reserved;
    bit<8>  next_proto;
    bit<8>  length;
}

header int_header_t { /* 8 */
    bit<4>  ver;
    bit<2>  rep;
    bit<1>  c;
    bit<1>  e;
    bit<1>  m;
    bit<10> rsvd1;
    bit<5>  meta_len;
    bit<8>  remaining_hop_cnt;
    bit<16> instructions;
    bit<16> rsvd2;
}

header int_metadata_t { /* 12 */
    bit<32>  switch_id;
    bit<48>  orig_mac;
    bit<16>  reserved;
}

struct fwd_meta_t {
    bit<32> l2ptr;
    bit<24> out_bd;
}

struct metadata {
    fwd_meta_t fwd;
}

struct headers {
    ethernet_t     ethernet;
    ipv4_t         ipv4;
    int_ip_shim_t  int_shim;
    int_header_t   int_header;
    int_metadata_t int_meta;
    int_metadata_t int_meta_2;
    udp_t          udp;
}
