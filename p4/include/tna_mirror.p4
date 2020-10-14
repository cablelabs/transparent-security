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
//const bit<3> EGR_PORT_MIRROR = 2;

/*** Internal Headers ***/

typedef bit<4> header_type_t;
typedef bit<4> header_info_t;

//const header_type_t HEADER_TYPE_BRIDGE         = 0xB;
const header_type_t HEADER_TYPE_MIRROR_INGRESS = 0xC;
//const header_type_t HEADER_TYPE_MIRROR_EGRESS  = 0xD;
//const header_type_t HEADER_TYPE_RESUBMIT       = 0xA;

/*
@flexible
header mirror_bridged_metadata_h {
    pkt_type_t pkt_type;
    bit<1> do_egr_mirroring;  //  Enable egress mirroring
    MirrorId_t egr_mir_ses;   // Egress mirror session ID
}
*/

header mirror_h {
    pkt_type_t  pkt_type;
}

const pkt_type_t PKT_TYPE_NORMAL = 1;
const pkt_type_t PKT_TYPE_MIRROR = 2;

struct custom_metadata_t {
    header_type_t  mirror_header_type;
    header_info_t  mirror_header_info;
    PortId_t       ingress_port;
    MirrorId_t     mirror_session;
    bit<48>        ingress_mac_tstamp;
    bit<48>        ingress_global_tstamp;
    bit<1>         ipv4_csum_err;
    pkt_type_t     pkt_type;
}
