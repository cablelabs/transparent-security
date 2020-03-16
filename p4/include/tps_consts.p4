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
const bit<8> MAX_HOPS = 0xa;

const bit<4> INT_SHIM_TYPE = 0x1;
const bit<16> INT_SHIM_DOMAIN_ID = 0x5453;
const bit<2> INT_SHIM_NPT_UDP_FULL_WRAP = 0x2;
const bit<4> INT_VERSION = 0x2;
const bit<5> INT_META_LEN = 0x1;
const bit<16> UDP_INT_SRC_PORT = 0x0;
const bit<16> UDP_INT_DST_PORT = 0x022b;
const bit<16> TPS_UDP_PORT = 0x216b;
const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_IPV6 = 0x86dd;
const bit<8> TYPE_TCP = 0x06;
const bit<8> TYPE_UDP = 0x11;

const bit<32> MAX_DEVICE_ID = 15;
const bit<9> DROP_PORT = 511;
const bit<1> TRUE = 0x1;
const bit<1> FALSE = 0x0;
