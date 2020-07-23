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
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control TpsVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
#ifdef BMV2
        verify_checksum(hdr.ipv4.isValid(),
            {
	        hdr.ipv4.version,
	        hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );

	verify_checksum(hdr.udp_int.isValid(),
            {
                hdr.udp_int.src_port,
                hdr.udp_int.dst_port,
                hdr.udp_int.len
            },
            hdr.udp_int.cksum,
            HashAlgorithm.csum16
        );
#endif
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control TpsComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
#ifdef BMV2
        update_checksum(hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );

        update_checksum(hdr.trpt_ipv4.isValid(),
            {
                hdr.trpt_ipv4.version,
                hdr.trpt_ipv4.ihl,
                hdr.trpt_ipv4.diffserv,
                hdr.trpt_ipv4.totalLen,
                hdr.trpt_ipv4.identification,
                hdr.trpt_ipv4.flags,
                hdr.trpt_ipv4.fragOffset,
                hdr.trpt_ipv4.ttl,
                hdr.trpt_ipv4.protocol,
                hdr.trpt_ipv4.srcAddr,
                hdr.trpt_ipv4.dstAddr
            },
            hdr.trpt_ipv4.hdrChecksum,
            HashAlgorithm.csum16
        );

	update_checksum(hdr.udp.isValid(),
            {
                hdr.udp.src_port,
                hdr.udp.dst_port,
                hdr.udp.len
            },
            hdr.udp.cksum,
            HashAlgorithm.csum16
        );

	update_checksum(hdr.udp_int.isValid(),
            {
                hdr.udp_int.src_port,
                hdr.udp_int.dst_port,
                hdr.udp_int.len
            },
            hdr.udp_int.cksum,
            HashAlgorithm.csum16
        );

	update_checksum(hdr.trpt_udp.isValid(),
            {
                hdr.trpt_udp.src_port,
                hdr.trpt_udp.dst_port,
                hdr.trpt_udp.len
            },
            hdr.trpt_udp.cksum,
            HashAlgorithm.csum16
        );
#endif
    }
}
