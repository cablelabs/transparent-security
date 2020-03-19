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
/* The default table size */
/* TODO - make this configurable at compile time */
#define TABLE_SIZE 1024
/* The INT Shim length at the gateway */
#define INT_SHIM_BASE_SIZE 7
/* Amount to add to the INT Shim length at each hop */
#define INT_SHIM_HOP_SIZE 1
/* Number of bytes per INT Shim length */
#define BYTES_PER_SHIM 4
/* Number of bytes used by a UDP header */
#define UDP_HDR_BYTES 8
/* Number of bytes used by a TCP header */
#define TCP_HDR_BYTES 20
/* Number of bytes used by an IPv6 header */
#define IPV6_HDR_BYTES 40

/* Start value for INT Header remaining_hop_cnt */
const bit<8> MAX_HOPS = 0xa;
/* Value of INT Shim type */
const bit<4> INT_SHIM_TYPE = 0x1;
/* Value of INT Shim domain_id */
const bit<16> INT_SHIM_DOMAIN_ID = 0x5453;
/* Value of INT Shim npt as we are fully wrapping the initial UDP header */
const bit<2> INT_SHIM_NPT_UDP_FULL_WRAP = 0x2;
/* The supported INT version */
const bit<4> INT_VERSION = 0x2;
/* Value of the INT header meta_len */
const bit<5> INT_META_LEN = 0x1;
/* The expected UDP INT header source port value */
const bit<16> UDP_INT_SRC_PORT = 0x0;
/* The expected UDP INT header destination port value */
const bit<16> UDP_INT_DST_PORT = 0x022b;
/* The Ethernet type of IPv4 */
const bit<16> TYPE_IPV4 = 0x0800;
/* The Ethernet type of IPv6 */
const bit<16> TYPE_IPV6 = 0x86dd;
/* The IP protocol or IPv6 next header protocol value for TCP */
const bit<8> TYPE_TCP = 0x06;
/* The IP protocol or IPv6 next header protocol value for UDP */
const bit<8> TYPE_UDP = 0x11;
/* For marking header bits True */
const bit<1> TRUE = 0x1;
/* For marking header bits False */
const bit<1> FALSE = 0x0;

/* Used for counters and this looks like it should be either compile or runtime configurable */
const bit<32> MAX_DEVICE_ID = 15;
/* The drop port to check at the ingress but is this really correct??? */
const bit<9> DROP_PORT = 511;
