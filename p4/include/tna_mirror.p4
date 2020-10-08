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

typedef bit<3> mirror_type_t;
typedef bit<8> pkt_type_t;

/* Ingress mirroring information */
const bit<3> ING_PORT_MIRROR = 1;
const bit<3> EGR_PORT_MIRROR = 2;

/*
const pkt_type_t PKT_TYPE_NORMAL = 1;
const pkt_type_t PKT_TYPE_MIRROR = 2;
const mirror_type_t MIRROR_TYPE_I2E = 1;
const mirror_type_t MIRROR_TYPE_E2E = 2;

struct mirror_metadata_t {
    header_type_t  mirror_header_type;
    header_info_t  mirror_header_info;
    PortId_t       ingress_port;
    MirrorId_t     mirror_session;
    bit<48>        ingress_mac_tstamp;
    bit<48>        ingress_global_tstamp;
    bit<1>         ipv4_csum_err;

    ip4Addr_t  ipv4_addr;
    ip6Addr_t  ipv6_addr;
    bit<16>    dst_port;
}
*/

/*** Internal Headers ***/

typedef bit<4> header_type_t;
typedef bit<4> header_info_t;

const header_type_t HEADER_TYPE_BRIDGE         = 0xB;
const header_type_t HEADER_TYPE_MIRROR_INGRESS = 0xC;
const header_type_t HEADER_TYPE_MIRROR_EGRESS  = 0xD;
const header_type_t HEADER_TYPE_RESUBMIT       = 0xA;

#define INTERNAL_HEADER         \
    header_type_t header_type;  \
    header_info_t header_info


header inthdr_h {
    INTERNAL_HEADER;
}

/* Bridged metadata */
header bridge_h {
    INTERNAL_HEADER;

#ifdef FLEXIBLE_HEADERS
    @flexible     PortId_t ingress_port;
    @flexible     bit<48>  ingress_mac_tstamp;
    @flexible     bit<48>  ingress_global_tstamp;
#else
    @padding
    bit<7> pad0;  PortId_t ingress_port;
                  bit<48>  ingress_mac_tstamp;
                  bit<48>  ingress_global_tstamp;
#endif
}


header ing_port_mirror_h {
    INTERNAL_HEADER;

#ifdef FLEXIBLE_HEADERS
    @flexible     PortId_t    ingress_port;
    @flexible     MirrorId_t  mirror_session;
    @flexible     bit<48>     ingress_mac_tstamp;
    @flexible     bit<48>     ingress_global_tstamp;
#else
    @padding bit<7> pad0;  PortId_t    ingress_port;
    @padding bit<6> pad1;  MirrorId_t  mirror_session;
                           bit<48>     ingress_mac_tstamp;
                           bit<48>     ingress_global_tstamp;
#endif
}

header egr_port_mirror_h {
    INTERNAL_HEADER;

#ifdef FLEXIBLE_HEADERS
    @flexible  PortId_t    ingress_port;
    @flexible  PortId_t    egress_port;
    @flexible  MirrorId_t  mirror_session;
    @flexible  bit<16>     pkt_length;
    @flexible  bit<48>     ingress_mac_tstamp;
    @flexible  bit<48>     ingress_global_tstamp;
    @flexible  bit<48>     egress_global_tstamp;
    /* The fields below are great for telemetry, but won't work on the model */
#ifdef TOFINO_TELEMETRY
    @flexible  bit<19>     enq_qdepth;
    @flexible  bit<2>      enq_congest_stat;
    @flexible  bit<18>     enq_tstamp;
    @flexible  bit<19>     deq_qdepth;
    @flexible  bit<2>      deq_congest_stat;
    @flexible  bit<8>      app_pool_congest_stat;
    @flexible  bit<18>     deq_timedelta;
    @flexible  bit<5>      egress_qid;
    @flexible  bit<3>      egress_cos;
    @flexible  bit<1>      deflection_flag;
#endif
#else
    @padding bit<7>  pad0;  PortId_t    ingress_port;
    @padding bit<7>  pad1;  PortId_t    egress_port;
    @padding bit<6>  pad2;  MirrorId_t  mirror_session;
                            bit<16>     pkt_length;
                            bit<48>     ingress_mac_tstamp;
                            bit<48>     ingress_global_tstamp;
                            bit<48>     egress_global_tstamp;
    /* The fields below are great for telemetry, but won't work on the model */
#ifdef TOFINO_TELEMETRY
    @padding bit<5>  pad3;  bit<19>     enq_qdepth;
    @padding bit<6>  pad4;  bit<2>      enq_congest_stat;
    @padding bit<14> pad5;  bit<18>     enq_tstamp;
    @padding bit<5>  pad6;  bit<19>     deq_qdepth;
    @padding bit<6>  pad7;  bit<2>      deq_congest_stat;
                            bit<8>      app_pool_congest_stat;
    @padding bit<14> pad8;  bit<18>     deq_timedelta;
    @padding bit<3>  pad9;  bit<5>      egress_qid;
    @padding bit<5>  pad10; bit<3>      egress_cos;
    @padding bit<7>  pad11; bit<1>      deflection_flag;
#endif
#endif /* FLEXIBLE_HEADERS */
}

struct ingress_metadata_t {
    header_type_t  mirror_header_type;
    header_info_t  mirror_header_info;
    PortId_t       ingress_port;
    MirrorId_t     mirror_session;
    bit<48>        ingress_mac_tstamp;
    bit<48>        ingress_global_tstamp;
    bit<1>         ipv4_csum_err;
}

struct egress_metadata_t {
    inthdr_h           inthdr;
    bridge_h           bridge;
    MirrorId_t         mirror_session;
    ing_port_mirror_h  ing_port_mirror;
    egr_port_mirror_h  egr_port_mirror;
    header_type_t      mirror_header_type;
    header_info_t      mirror_header_info;
    MirrorId_t         egr_mirror_session;
    bit<16>            egr_mirror_pkt_length;
}
