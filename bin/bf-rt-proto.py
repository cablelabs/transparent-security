################################################################################
# BAREFOOT NETWORKS CONFIDENTIAL & PROPRIETARY
#
# Copyright (c) 2019-present Barefoot Networks, Inc.
#
# All Rights Reserved.
#
# NOTICE: All information contained herein is, and remains the property of
# Barefoot Networks, Inc. and its suppliers, if any. The intellectual and
# technical concepts contained herein are proprietary to Barefoot Networks, Inc.
# and its suppliers and may be covered by U.S. and Foreign Patents, patents in
# process, and are protected by trade secret or copyright law.  Dissemination of
# this information or reproduction of this material is strictly forbidden unless
# prior written permission is obtained from Barefoot Networks, Inc.
#
# No warranty, explicit or implicit is provided, unless granted under a written
# agreement with Barefoot Networks, Inc.
#
################################################################################

import logging
import math
import queue
import random
import threading
import time
from collections import namedtuple

import grpc
import ptf
from tofino.google.rpc import code_pb2
from p4testutils.bfruntime_base_tests import BfRtInfo, printGrpcError, \
    BfRuntimeTest

from ptf import config
from ptf.thriftutils import *
import ptf.testutils as testutils
from ptf.base_tests import BaseTest
from tofino.bfrt_grpc import bfruntime_pb2_grpc
from tofino.bfrt_grpc import bfruntime_pb2
import tofino.bfrt_grpc.client as gc
import codecs

logger = logging.getLogger('Test')
if not len(logger.handlers):
    logger.addHandler(logging.StreamHandler())

swports = []
for device, port, ifname in config["interfaces"]:
    swports.append(port)
    swports.sort()

if swports == []:
    swports = list(range(9))


def port_to_pipe(port):
    local_port = port & 0x7F
    assert (local_port < 72)
    pipe = (port >> 7) & 0x3
    assert (port == ((pipe << 7) | local_port))
    return pipe


swports_0 = []
swports_1 = []
swports_2 = []
swports_3 = []
for port in swports:
    pipe = port_to_pipe(port)
    if pipe == 0:
        swports_0.append(port)
    elif pipe == 1:
        swports_1.append(port)
    elif pipe == 2:
        swports_2.append(port)
    elif pipe == 3:
        swports_3.append(port)


def get_port_metadata_table_name(profile):
    if profile == 0:
        return "pipeline_profile_a.SwitchIngressParser_a.$PORT_METADATA"
    elif profile == 1:
        return "pipeline_profile_b.SwitchIngressParser_b.$PORT_METADATA"
    else:
        assert (0)


def to_bytes_right_pad(n):
    """ Convert integers to right padded bytearray """
    if testutils.test_param_get("arch") == "tofino":
        length = 8
    elif testutils.test_param_get("arch") == "tofino2":
        length = 16
    else:
        assert (0)
    h = '%x' % n
    s = codecs.decode(('0' * (len(h) % 2) + h).ljust(length * 2, '0'), "hex")
    return bytearray(s)


def get_ig_eg_ports_profA(pipe0):
    if pipe0 == 0:
        ig_port0 = swports_0[0]
        eg_port0 = swports_0[1]
    elif pipe0 == 1:
        ig_port0 = swports_1[0]
        eg_port0 = swports_1[1]
    elif pipe0 == 2:
        ig_port0 = swports_2[0]
        eg_port0 = swports_2[1]
    elif pipe0 == 3:
        ig_port0 = swports_3[0]
        eg_port0 = swports_3[1]
    return ig_port0, eg_port0


def get_ig_eg_ports_profB(pipe1):
    if pipe1 == 0:
        ig_port1 = swports_0[0]
        eg_port1 = swports_0[0]
    elif pipe1 == 1:
        ig_port1 = swports_1[0]
        eg_port1 = swports_1[0]
    elif pipe1 == 2:
        ig_port1 = swports_2[0]
        eg_port1 = swports_2[0]
    elif pipe1 == 3:
        ig_port1 = swports_3[0]
        eg_port1 = swports_3[0]
    return ig_port1, eg_port1


def get_internal_or_external_pipe(is_internal):
    for pipe in (0, 4):
        if pipe == 0:
            port = swports_0[0]
        elif pipe == 1:
            port = swports_1[0]
        elif pipe == 2:
            port = swports_2[0]
        elif pipe == 3:
            port = swports_3[0]
        result = testutils.pal.pal_is_port_internal(dev_id, port)
        if (is_internal) and (result):
            return pipe
        if (not is_internal) and (not result):
            return pipe
    assert (0)


def verify_cntr_inc(test, all_devtgt, all_pipes, all_ports, all_ttl, all_macs,
                    all_ip, all_custom_tags, num_pkts):
    target = all_devtgt
    pipe0, pipe1 = all_pipes
    ig_port0, eg_port0, ig_port1, eg_port1, invalid_port = all_ports
    ig_ttl0, eg_ttl1, ig_ttl1, eg_ttl0 = all_ttl
    dmac, smac = all_macs
    dip, sip = all_ip
    ig_tag0, eg_tag1, ig_tag1, eg_tag0 = all_custom_tags

    logger.info("Verifying counter got incremented on pipe0 egress")

    logger.info("  Get Table entry")
    resp = test.a_forward_e.entry_get(target,
                                      [test.a_forward_e.make_key(
                                          [gc.KeyTuple('hdr.ipv4.dst_addr',
                                                       gc.ipv4_to_bytes(dip),
                                                       gc.ipv4_to_bytes(dip)),
                                           gc.KeyTuple('hdr.ipv4.ttl', eg_ttl0,
                                                       eg_ttl0),
                                           gc.KeyTuple(
                                               'hdr.custom_metadata.custom_tag',
                                               eg_tag0, eg_tag0),
                                           gc.KeyTuple('$MATCH_PRIORITY',
                                                       0)])],
                                      {"from_hw": True},
                                      test.a_forward_e.make_data(
                                          [gc.DataTuple("$COUNTER_SPEC_BYTES"),
                                           gc.DataTuple("$COUNTER_SPEC_PKTS")],
                                          'SwitchEgress_a.hit',
                                          get=True))

    # parse resp to get the counter
    data_dict = next(resp)[0].to_dict()
    recv_pkts = data_dict["$COUNTER_SPEC_PKTS"]
    recv_bytes = data_dict["$COUNTER_SPEC_BYTES"]

    if (num_pkts != recv_pkts):
        logger.error("Error! packets sent = %s received count = %s",
                     str(num_pkts), str(recv_pkts))
        assert 0

    # Default packet size is 100 bytes and model adds 4 bytes of CRC
    # Add 2 bytes for the custom metadata header
    pkt_size = 100 + 4 + 2
    num_bytes = num_pkts * pkt_size

    if (num_bytes != recv_bytes):
        logger.error("Error! bytes sent = %s received count = %s",
                     str(num_bytes), str(recv_bytes))
        assert 0


def get_all_tables(test):
    test.a_pinning = test.bfrt_info.table_get("SwitchIngress_a.pinning")
    # Some of these tables can be retrieved using a lesser qualified name lke storm_control
    # since it is not present in any other control block of the P4 program like pinning or
    # or forward.
    test.a_storm_control = test.bfrt_info.table_get("storm_control")
    test.a_stats = test.bfrt_info.table_get("stats")
    test.a_forward_i = test.bfrt_info.table_get("SwitchIngress_a.forward")
    test.a_forward_e = test.bfrt_info.table_get("SwitchEgress_a.forward")
    test.a_encap = test.bfrt_info.table_get("encap_custom_metadata_hdr")
    test.a_decap = test.bfrt_info.table_get("decap_custom_metadata_hdr")

    test.b_pinning = test.bfrt_info.table_get("SwitchIngress_b.pinning")
    test.b_forward_i = test.bfrt_info.table_get("SwitchIngress_b.forward")
    test.b_forward_e = test.bfrt_info.table_get("SwitchEgress_b.forward")


def program_pinning(test, all_devtgt, all_pipes, all_ports):
    target = all_devtgt
    pipe0, pipe1 = all_pipes
    ig_port0, eg_port0, ig_port1, eg_port1, invalid_port = all_ports

    logger.info("Programming pinning entries")

    logger.info(" Programming pinning entries on ingress pipe %d ", pipe0)
    test.a_pinning.entry_add(
        target,
        [test.a_pinning.make_key(
            [gc.KeyTuple('ig_intr_md.ingress_port', ig_port0)])],
        [test.a_pinning.make_data(
            [gc.DataTuple('port', eg_port1)],
            'SwitchIngress_a.modify_eg_port')])

    logger.info(" Programming pinning entries on ingress pipe %d ", pipe1)
    test.b_pinning.entry_add(
        target,
        [test.b_pinning.make_key(
            [gc.KeyTuple('ig_intr_md.ingress_port', ig_port1)])],
        [test.b_pinning.make_data([gc.DataTuple('port', eg_port0)],
                                  'SwitchIngress_b.modify_eg_port')])


def delete_pinning(test, all_devtgt, all_pipes, all_ports):
    target = all_devtgt
    pipe0, pipe1 = all_pipes
    ig_port0, eg_port0, ig_port1, eg_port1, invalid_port = all_ports

    logger.info("Deleting pinning entries")

    logger.info(" Deleting pinning entries on ingress pipe %d ", pipe0)
    test.a_pinning.entry_del(
        target,
        [test.a_pinning.make_key(
            [gc.KeyTuple('ig_intr_md.ingress_port', ig_port0)])])

    logger.info(" Deleting pinning entries on ingress pipe  %d ", pipe1)
    test.b_pinning.entry_del(
        target,
        [test.b_pinning.make_key(
            [gc.KeyTuple('ig_intr_md.ingress_port', ig_port1)])])


def program_entries(test, all_devtgt, all_pipes, all_ports, all_ttl, all_macs,
                    all_ip, all_custom_tags):
    target = all_devtgt
    pipe0, pipe1 = all_pipes
    ig_port0, eg_port0, ig_port1, eg_port1, invalid_port = all_ports
    ig_ttl0, eg_ttl1, ig_ttl1, eg_ttl0 = all_ttl
    dmac, smac = all_macs
    dip, sip = all_ip
    ig_tag0, eg_tag1, ig_tag1, eg_tag0 = all_custom_tags
    meter_idx = 1
    color = 0

    logger.info("Programming table entries")

    logger.info(" Programming table entries on ingress pipe %d ", pipe0)
    logger.info("    Table: storm_control")
    test.a_storm_control.entry_add(
        target,
        [test.a_storm_control.make_key(
            [gc.KeyTuple('ig_intr_md.ingress_port', ig_port0)])],
        [test.a_storm_control.make_data(
            [gc.DataTuple('index', meter_idx)],
            'SwitchIngress_a.set_color')])

    logger.info("    Table: stats")
    test.a_stats.entry_add(
        target,
        [test.a_stats.make_key(
            [gc.KeyTuple('qos_md.color', color),
             gc.KeyTuple('ig_intr_md.ingress_port', ig_port0)])],
        [test.a_stats.make_data([], "SwitchIngress_a.count")])

    logger.info("    Table: forward")
    test.a_forward_i.entry_add(
        target,
        [test.a_forward_i.make_key(
            [gc.KeyTuple('hdr.ethernet.dst_addr', gc.mac_to_bytes(dmac)),
             gc.KeyTuple('hdr.ipv4.ttl', ig_ttl0)])],
        [test.a_forward_i.make_data([], 'SwitchIngress_a.hit')])

    logger.info("    Table: encap_custom_metadata_hdr")
    test.a_encap.entry_add(
        target,
        [test.a_encap.make_key(
            [gc.KeyTuple('hdr.ethernet.$valid', 1)])],
        [test.a_encap.make_data(
            [gc.DataTuple('tag', ig_tag0)],
            'SwitchIngress_a.encap_custom_metadata')])

    logger.info(" Programming table entries on egress pipe %d ", pipe1)
    logger.info("    Table: forward")
    test.b_forward_e.entry_add(
        target,
        [test.b_forward_e.make_key(
            [gc.KeyTuple('hdr.ipv4.dst_addr', gc.ipv4_to_bytes(dip),
                         prefix_len=31),
             gc.KeyTuple('hdr.ipv4.ttl', eg_ttl1),
             gc.KeyTuple('hdr.custom_metadata.custom_tag', eg_tag1)])],
        [test.b_forward_e.make_data([], "SwitchEgress_b.hit")])

    logger.info(" Programming table entries on ingress pipe %d ", pipe1)
    logger.info("    Table: forward")
    test.b_forward_i.entry_add(
        target,
        [test.b_forward_i.make_key(
            [gc.KeyTuple('hdr.ipv4.dst_addr', gc.ipv4_to_bytes(dip)),
             gc.KeyTuple('hdr.ipv4.ttl', ig_ttl1),
             gc.KeyTuple('hdr.custom_metadata.custom_tag', ig_tag1)])],
        [test.b_forward_i.make_data([], "SwitchIngress_b.hit")])

    # No need to program learning table as default action is to learn
    logger.info(" Programming table entries on egress pipe %d ", pipe0)
    logger.info("    Table: forward")
    test.a_forward_e.entry_add(
        target,
        [test.a_forward_e.make_key(
            [gc.KeyTuple('hdr.ipv4.dst_addr', gc.ipv4_to_bytes(dip),
                         gc.ipv4_to_bytes(dip)),
             gc.KeyTuple('hdr.ipv4.ttl', eg_ttl0, eg_ttl0),
             gc.KeyTuple('hdr.custom_metadata.custom_tag', eg_tag0, eg_tag0),
             gc.KeyTuple('$MATCH_PRIORITY', 0)])],
        [test.a_forward_e.make_data(
            [gc.DataTuple('$COUNTER_SPEC_BYTES', 0),
             gc.DataTuple('$COUNTER_SPEC_PKTS', 0)],
            'SwitchEgress_a.hit')])

    logger.info("    Table: decap_custom_metadata_hdr")
    test.a_decap.entry_add(
        target,
        [test.a_decap.make_key(
            [gc.KeyTuple('hdr.custom_metadata.$valid', 1)])],
        [test.a_decap.make_data([], 'SwitchEgress_a.decap_custom_metadata')])


def delete_entries(test, all_devtgt, all_pipes, all_ports, all_ttl, all_macs,
                   all_ip, all_custom_tags):
    target = all_devtgt
    pipe0, pipe1 = all_pipes
    ig_port0, eg_port0, ig_port1, eg_port1, invalid_port = all_ports
    ig_ttl0, eg_ttl1, ig_ttl1, eg_ttl0 = all_ttl
    dmac, smac = all_macs
    dip, sip = all_ip
    ig_tag0, eg_tag1, ig_tag1, eg_tag0 = all_custom_tags
    color = 0

    logger.info("Deleting table entries")

    logger.info(" Deleting table entries on ingress pipe %d ", pipe0)
    logger.info("    Table: storm_control")
    test.a_storm_control.entry_del(
        target,
        [test.a_storm_control.make_key(
            [gc.KeyTuple('ig_intr_md.ingress_port', ig_port0)])])

    logger.info("    Table: stats")
    test.a_stats.entry_del(
        target,
        [test.a_stats.make_key(
            [gc.KeyTuple('qos_md.color', color),
             gc.KeyTuple('ig_intr_md.ingress_port', ig_port0)])])

    logger.info("    Table: forward")
    test.a_forward_i.entry_del(
        target,
        [test.a_forward_i.make_key(
            [gc.KeyTuple('hdr.ethernet.dst_addr', gc.mac_to_bytes(dmac)),
             gc.KeyTuple('hdr.ipv4.ttl', ig_ttl0)])])

    logger.info("    Table: encap_custom_metadata_hdr")
    test.a_encap.entry_del(
        target,
        [test.a_encap.make_key(
            [gc.KeyTuple('hdr.ethernet.$valid', 1)])])

    logger.info(" Deleting table entries on egress pipe %d ", pipe1)
    logger.info("    Table: forward")
    test.b_forward_e.entry_del(
        target,
        [test.b_forward_e.make_key(
            [gc.KeyTuple('hdr.ipv4.dst_addr', gc.ipv4_to_bytes(dip),
                         prefix_len=31),
             gc.KeyTuple('hdr.ipv4.ttl', eg_ttl1),
             gc.KeyTuple('hdr.custom_metadata.custom_tag', eg_tag1)])])

    logger.info(" Deleting table entries on ingress pipe %d ", pipe1)
    logger.info("    Table: forward")
    test.b_forward_i.entry_del(
        target,
        [test.b_forward_i.make_key(
            [gc.KeyTuple('hdr.ipv4.dst_addr', gc.ipv4_to_bytes(dip)),
             gc.KeyTuple('hdr.ipv4.ttl', ig_ttl1),
             gc.KeyTuple('hdr.custom_metadata.custom_tag', ig_tag1)])])

    logger.info(" Deleting table entries on %d egress pipe ", pipe0)
    logger.info("    Table: forward")
    test.a_forward_e.entry_del(
        target,
        [test.a_forward_e.make_key(
            [gc.KeyTuple('hdr.ipv4.dst_addr', gc.ipv4_to_bytes(dip),
                         gc.ipv4_to_bytes(dip)),
             gc.KeyTuple('hdr.ipv4.ttl', eg_ttl0, eg_ttl0),
             gc.KeyTuple('hdr.custom_metadata.custom_tag', eg_tag0, eg_tag0),
             gc.KeyTuple('$MATCH_PRIORITY', 0)])])

    logger.info("    Table: decap_custom_metadata_hdr")
    test.a_decap.entry_del(
        target,
        [test.a_decap.make_key(
            [gc.KeyTuple('hdr.custom_metadata.$valid', 1)])])


# Symmetric table test. Program tables in both pipeline profiles symmetrically.
# Send packet on pipe 0 ingress and expect it to go to pipe 1 and then finally
# egress on pipe 0 egress.
# Pipe0 ingrss -> Pipe 1 Egress -> Pipe 1 Ingress -> Pipe 0 Egress
class Sym32Q(BfRuntimeTest):
    def setUp(self):
        client_id = 0
        p4_name = "tna_32q_2pipe"
        BfRuntimeTest.setUp(self, client_id, p4_name)

    def runTest(self):
        logger.info("")
        if testutils.test_param_get('target') == "hw":
            # Pal API not available in BRI, hard-code pipes till then
            '''
            # Get External pipe (should be either pipe 0 or 2, profileA)
            pipe0 = get_internal_or_external_pipe(self, 0)
            assert(pipe0 == 0 or pipe0 == 2)
            # Get Internal pipe (should be either pipe 1 or 3, profileB)
            pipe1 = get_internal_or_external_pipe(self, 1)
            assert(pipe1 == 1 or pipe1 == 3)
            '''
            pipe0 = 0
            pipe1 = 1
        else:
            pipe0 = 0
            pipe1 = 1

        logger.info("Pipe0 %d, Pipe1 %d", pipe0, pipe1)

        # Get bfrt_info and set it as part of the test
        self.bfrt_info = self.interface.bfrt_info_get("tna_32q_2pipe")

        assert (pipe0 != pipe1)

        ig_port0, eg_port0 = get_ig_eg_ports_profA(pipe0)
        logger.info("ig_port0 %d, eg_port0 %d", ig_port0, eg_port0)

        ig_port1, eg_port1 = get_ig_eg_ports_profB(pipe1)
        logger.info("ig_port1 %d, eg_port1 %d", ig_port1, eg_port1)

        ig_ttl0 = 64
        eg_ttl1 = 63
        ig_ttl1 = 62
        eg_ttl0 = 61
        invalid_port = 511
        dmac = '22:33:44:55:66:77'
        smac = "00:11:22:33:44:55"
        dip = "5.6.7.8"
        sip = "1.2.3.4"
        ig_tag0 = 1
        eg_tag1 = 1  # Same as ig_tag0 as it is just set in ingress
        ig_tag1 = 2
        eg_tag0 = 3

        target = gc.Target(device_id=0, pipe_id=0xffff)
        all_devtgt = target
        all_pipes = pipe0, pipe1
        all_ports = ig_port0, eg_port0, ig_port1, eg_port1, invalid_port
        all_ttl = ig_ttl0, eg_ttl1, ig_ttl1, eg_ttl0
        all_macs = dmac, smac
        all_ip = dip, sip
        all_custom_tags = ig_tag0, eg_tag1, ig_tag1, eg_tag0

        get_all_tables(self)
        try:
            program_entries(self, all_devtgt, all_pipes, all_ports, all_ttl,
                            all_macs, all_ip, all_custom_tags)
            program_pinning(self, all_devtgt, all_pipes, all_ports)

            logger.info("Sending packet on port %d", ig_port0)
            pkt = testutils.simple_tcp_packet(eth_dst=dmac,
                                              eth_src=smac,
                                              ip_src=sip,
                                              ip_dst=dip,
                                              ip_ttl=ig_ttl0)
            testutils.send_packet(self, ig_port0, pkt)

            pkt.ttl = pkt.ttl - 4
            exp_pkt = pkt
            logger.info("Expecting packet on port %d", eg_port0)
            testutils.verify_packets(self, exp_pkt, [eg_port0])

            verify_cntr_inc(self, all_devtgt, all_pipes, all_ports, all_ttl,
                            all_macs, all_ip, all_custom_tags, 1)

        finally:
            delete_entries(self, all_devtgt, all_pipes, all_ports, all_ttl,
                           all_macs, all_ip, all_custom_tags)
            delete_pinning(self, all_devtgt, all_pipes, all_ports)
            logger.info("")
            logger.info("Sending another packet on port %d", ig_port0)
            pkt = testutils.simple_tcp_packet(eth_dst=dmac,
                                              eth_src=smac,
                                              ip_src=sip,
                                              ip_dst=dip,
                                              ip_ttl=ig_ttl0)
            testutils.send_packet(self, ig_port0, pkt)

            logger.info("Packet is expected to get dropped.")
            testutils.verify_no_other_packets(self)


class PortMetadataTest(BfRuntimeTest):
    def setUp(self):
        client_id = 0
        p4_name = "tna_32q_2pipe"
        BfRuntimeTest.setUp(self, client_id, p4_name)
        self.target = gc.Target(device_id=0, pipe_id=0xffff)

    def runTest(self):
        # Get bfrt_info and set it as part of the test
        bfrt_info = self.interface.bfrt_info_get("tna_32q_2pipe")

        # Try Adding entry in a port in profile a
        igr_port, egr_port = get_ig_eg_ports_profA(0)
        phase0data = 0x1122334455667788
        phase0data_padded = to_bytes_right_pad(phase0data)
        logger.info(
            "Adding PORT_METADATA table entry for igr port %d in profile A",
            igr_port)
        pmtable_1 = bfrt_info.table_get(get_port_metadata_table_name(0))
        pmtable_1.info.data_field_annotation_add("$DEFAULT_FIELD", None,
                                                 "bytes")
        pmtable_1.entry_add(
            self.target,
            [pmtable_1.make_key(
                [gc.KeyTuple("ig_intr_md.ingress_port", igr_port)])],
            [pmtable_1.make_data(
                [gc.DataTuple("$DEFAULT_FIELD", phase0data_padded)])])

        # Read and verify the entry
        resp = pmtable_1.entry_get(self.target,
                                   [pmtable_1.make_key([gc.KeyTuple(
                                       "ig_intr_md.ingress_port", igr_port)])],
                                   {"from_hw": True})
        fields = next(resp)[0].to_dict()
        logger.info("Verifying entry for igr port in profile a %d", igr_port)
        recv_data = fields["$DEFAULT_FIELD"]
        assert recv_data == phase0data_padded, "Exp data : %s : Rcv data : %s" \
                                               % (phase0data_padded, recv_data)

        # Now Try Adding entry in a port in profile b
        igr_port, egr_port = get_ig_eg_ports_profB(1)
        phase0data = 0x8877665544332211
        phase0data_padded = to_bytes_right_pad(phase0data)

        pmtable_2 = bfrt_info.table_get(get_port_metadata_table_name(1))
        pmtable_2.info.data_field_annotation_add("$DEFAULT_FIELD", None,
                                                 "bytes")
        logger.info(
            "Adding PORT_METADATA table entry for igr port %d in profile B",
            igr_port)
        pmtable_2.entry_add(
            self.target,
            [pmtable_2.make_key(
                [gc.KeyTuple("ig_intr_md.ingress_port", igr_port)])],
            [pmtable_2.make_data(
                [gc.DataTuple('$DEFAULT_FIELD', phase0data_padded)])])

        # Read and verify the entry
        resp = pmtable_2.entry_get(self.target,
                                   [pmtable_2.make_key([gc.KeyTuple(
                                       "ig_intr_md.ingress_port", igr_port)])],
                                   {"from_hw": True})
        fields = next(resp)[0].to_dict()
        logger.info("Verifying entry for igr port in profile b %d", igr_port)
        recv_data = fields["$DEFAULT_FIELD"]
        assert recv_data == phase0data_padded, "Exp data : %s : Rcv data : %s" \
                                               % (phase0data_padded, recv_data)


class BfRuntimeTest(BaseTest):
    def __init__(self):
        BaseTest.__init__(self)
        self.device_id = 0
        self.client_id = 0
        self._swports = []
        self.bfrt_info = None
        self.p4_name = ""

    def tearDown(self):
        self.tear_down_stream()
        BaseTest.tearDown(self)

    def setUp(self, client_id=None, p4_name=None, is_master=False):
        BaseTest.setUp(self)

        # Setting up PTF dataplane
        self.dataplane = ptf.dataplane_instance
        self.dataplane.flush()

        grpc_addr = testutils.test_param_get("grpc_server")
        if grpc_addr is None or grpc_addr is 'localhost':
            grpc_addr = 'localhost:50052'
        else:
            grpc_addr = grpc_addr + ":50052"

        if client_id:
            self.client_id = client_id
        else:
            self.client_id = 0

        if p4_name:
            self.p4_name = p4_name
        else:
            self.p4_name = ""

        gigabyte = 1024 ** 3
        self.channel = grpc.insecure_channel(grpc_addr, options=[
            ('grpc.max_send_message_length', gigabyte), (
                'grpc.max_receive_message_length', gigabyte),
            ('grpc.max_metadata_size', gigabyte)])

        self.stub = bfruntime_pb2_grpc.BfRuntimeStub(self.channel)

        self.set_up_stream()

        # Subscribe to receive notifications
        num_tries = 5
        cur_tries = 0
        success = False
        while cur_tries < num_tries and not success:
            self.subscribe(is_master)
            logger.info("Subscribe attempt #%d", cur_tries + 1)
            # Wait for 5 seconds max for each attempt
            success = self.is_subscribe_successful(5)
            cur_tries += 1
        # Set forwarding pipeline config (For the time being we are just
        # associating a client with a p4). Currently the grpc server supports
        # only one client to be in-charge of one p4.
        if p4_name and p4_name != "":
            self.bindPipelineConfig()

    def bindPipelineConfig(self):
        req = bfruntime_pb2.SetForwardingPipelineConfigRequest()
        req.client_id = self.client_id
        req.action = bfruntime_pb2.SetForwardingPipelineConfigRequest.BIND
        config = req.config.add()
        config.p4_name = self.p4_name
        logger.info("Binding with p4_name " + self.p4_name)
        try:
            self.stub.SetForwardingPipelineConfig(req)
        except grpc.RpcError as e:
            if e.code() != grpc.StatusCode.UNKNOWN:
                raise e
        logger.info("Binding with p4_name %s successful!!", self.p4_name)

    InputConfig = namedtuple('Input_config',
                             'profile_name context_file binary_file pipe_scope')
    InputConfig.__new__.__defaults__ = ("", "", "", [])

    def addConfigToSetForwardRequest(self, req, p4_name, bfruntime_info,
                                     input_profiles):
        def read_file(file_name):
            data = ""
            with open(file_name, 'r') as myfile:
                data = myfile.read()
            return data

        config = req.config.add()
        config.p4_name = p4_name
        config.bfruntime_info = read_file(bfruntime_info)
        for input_profile in input_profiles:
            profile = config.profiles.add()
            profile.profile_name = input_profile.profile_name
            profile.context = read_file(input_profile.context_file)
            profile.binary = read_file(input_profile.binary_file)
            profile.pipe_scope.extend(input_profile.pipe_scope)

    def write(self, req):
        req.client_id = self.client_id
        try:
            self.stub.Write(req)
        except grpc.RpcError as e:
            printGrpcError(e)
            raise e

    def read(self, req):
        try:
            return self.stub.Read(req)
        except grpc.RpcError as e:
            printGrpcError(e)
            raise e

    # Most of these helper functions are borrowed from p4runtime_base_test
    # See https://github.com/barefootnetworks/bf-p4c-compilers/blob/master/p4-tests/base_test.py
    def set_up_stream(self):
        self._stream_out_q = queue.Queue()
        self._stream_in_q = queue.Queue()
        self._exception_q = queue.Queue()

        def stream_iterator():
            while True:
                p = self._stream_out_q.get()
                if p is None:
                    break
                yield p

        def stream_recv(stream):
            try:
                for p in stream:
                    self._stream_in_q.put(p)
            except grpc.RpcError as e:
                self._exception_q.put(e)

        self.stream = self.stub.StreamChannel(stream_iterator())
        self._stream_recv_thread = threading.Thread(
            target=stream_recv, args=(self.stream,))
        self._stream_recv_thread.start()

    def subscribe(self, is_master):
        req = bfruntime_pb2.StreamMessageRequest()
        req.client_id = self.client_id
        req.subscribe.is_master = is_master
        req.subscribe.device_id = self.device_id
        req.subscribe.notifications.enable_learn_notifications = True
        req.subscribe.notifications.enable_idletimeout_notifications = True
        req.subscribe.notifications.enable_port_status_change_notifications = True
        self._stream_out_q.put(req)

    def get_packet_in(self, timeout=1):
        pass

    def is_subscribe_successful(self, timeout=1):
        msg = self.get_stream_message("subscribe", timeout)
        if msg is None:
            logger.info("Subscribe timeout exceeded %ds", timeout)
            return False
        else:
            logger.info("Subscribe response received %d",
                        msg.subscribe.status.code)
            if (msg.subscribe.status.code != code_pb2.OK):
                logger.info("Subscribe failed")
                return False
        return True

    def is_set_fwd_action_done(self, value_to_check_for, timeout=1):
        msg = self.get_stream_message(
            "set_forwarding_pipeline_config_response", timeout)
        if msg is None:
            logger.info("commit notification expectation exceeded %ds",
                        timeout)
            return False
        else:
            if (msg.set_forwarding_pipeline_config_response.
                    set_forwarding_pipeline_config_response_type == value_to_check_for ==
                    bfruntime_pb2.SetForwardingPipelineConfigResponseType.Value(
                        "WARM_INIT_STARTED")):
                logger.info("WARM_INIT_STARTED received")
                return True
            elif (msg.set_forwarding_pipeline_config_response.
                          set_forwarding_pipeline_config_response_type == value_to_check_for ==
                  bfruntime_pb2.SetForwardingPipelineConfigResponseType.Value(
                      "WARM_INIT_FINISHED")):
                logger.info("WARM_INIT_FINISHED received")
                return True
        return False

    def get_digest(self, timeout=1):
        msg = self.get_stream_message("digest", timeout)
        if msg is None:
            self.fail("Digest list not received.")
        else:
            return msg.digest

    def get_bfrt_info(self, p4_name="", timeout=1):
        # send a request
        req = bfruntime_pb2.GetForwardingPipelineConfigRequest()
        req.device_id = self.device_id
        req.client_id = self.client_id
        msg = self.stub.GetForwardingPipelineConfig(req)

        # get the reply
        if msg is None:
            self.fail("BF_RT_INFO not received")
        else:
            if (p4_name == ""):
                return msg.config[0].bfruntime_info
            for config in msg.config:
                logger.info("Received %s on GetForwarding", config.p4_name)
            for config in msg.config:
                if (p4_name == config.p4_name):
                    return msg.config[0].bfruntime_info
            self.fail("BF_RT_INFO not received")

    def parse_bfrt_info(self, data):
        return BfRtInfo(data)

    def set_bfrt_info(self, bfrt_info):
        self.bfrt_info = bfrt_info

    def get_idletime_notification(self, timeout=1):
        msg = self.get_stream_message("idle_timeout_notification", timeout)
        if msg is not None:
            return msg.idle_timeout_notification
        return None

    def get_portstatus_notification(self, timeout=1):
        msg = self.get_stream_message("port_status_change_notification",
                                      timeout)
        if msg is None:
            self.fail("port_status_change_notification not received.")
        else:
            return msg.port_status_change_notification

    def get_stream_message(self, type_, timeout=1):
        start = time.time()
        try:
            while True:
                remaining = timeout - (time.time() - start)
                if remaining < 0:
                    break
                msg = self._stream_in_q.get(timeout=remaining)
                if not msg.HasField(type_):
                    # Put the msg back in for someone else to read
                    # TODO make separate queues for each msg type
                    self._stream_in_q.put(msg)
                    continue
                return msg
        except:  # timeout expired
            pass
        return None

    def tear_down_stream(self):
        self._stream_out_q.put(None)
        self._stream_recv_thread.join()

    def get_table_local(self, table_name):
        for table_name_, table_ in self.bfrt_info.table_dict.iteritems():
            if (table_name_ == table_name):
                return table_.id

    def get_table(self, name):
        if self.bfrt_info:
            return self.get_table_local(name)
        req = bfruntime_pb2.ReadRequest()
        req.client_id = self.client_id;
        req.target.device_id = self.device_id

        object_id = req.entities.add().object_id
        object_id.table_object.table_name = name

        for rep in self.stub.Read(req):
            return rep.entities[0].object_id.id

    def get_action_local(self, table_name, action_name):
        table_obj = self.bfrt_info.table_dict[table_name]
        for action_name_, action_ in table_obj.action_dict.iteritems():
            if (action_name_ == action_name):
                return action_.id

    def get_action(self, table_name, action_name):
        """ Get action id for a given table and action. """
        if self.bfrt_info:
            return self.get_action_local(table_name, action_name)
        req = bfruntime_pb2.ReadRequest()
        req.client_id = self.client_id;
        req.target.device_id = self.device_id

        object_id = req.entities.add().object_id
        object_id.table_object.table_name = table_name
        object_id.table_object.action_name.action = action_name

        for rep in self.stub.Read(req):
            return rep.entities[0].object_id.id

    def get_data_field_local(self, table_name, action_name, field_name):
        table_obj = self.bfrt_info.table_dict[table_name]
        if action_name is not None:
            for action_name_, action_ in table_obj.action_dict.iteritems():
                if action_name_ == action_name:
                    for field_name_, data_ in action_.data_dict.iteritems():
                        if field_name_ == field_name:
                            return data_.id
        for field_name_, data_ in table_obj.data_dict.iteritems():
            if field_name_ == field_name:
                return data_.id
        return 0

    def get_data_field(self, table_name, action_name, field_name):
        """ Get data field id for a given table, action and field. """
        if self.bfrt_info:
            return self.get_data_field_local(table_name, action_name,
                                             field_name)
        req = bfruntime_pb2.ReadRequest()
        req.client_id = self.client_id;
        req.target.device_id = self.device_id

        object_id = req.entities.add().object_id
        object_id.table_object.table_name = table_name
        if action_name is not None:
            object_id.table_object.data_field_name.action = action_name
        object_id.table_object.data_field_name.field = field_name
        for rep in self.stub.Read(req):
            return rep.entities[0].object_id.id

    def get_learn_data_field_local(self, learn_name, field_name):
        learn_obj = self.bfrt_info.learn_dict[learn_name]
        for field_name_, data_ in learn_obj.data_dict.iteritems():
            if field_name_ == field_name:
                return data_.id
        return 0

    def get_learn_data_field(self, learn_name, field_name):
        """ Get data field id for a given table, action and field. """
        if self.bfrt_info:
            return self.get_learn_data_field_local(learn_name, field_name)
        req = bfruntime_pb2.ReadRequest()
        req.client_id = self.client_id;
        req.target.device_id = self.device_id

        object_id = req.entities.add().object_id
        object_id.learn_object.learn_name = learn_name
        object_id.learn_object.data_field_name.field = field_name
        for rep in self.stub.Read(req):
            return rep.entities[0].object_id.id

    def get_key_local(self, table_name, field_name):
        table_obj = self.bfrt_info.table_dict[table_name]
        for field_name_, key_ in table_obj.key_dict.iteritems():
            if field_name_ == field_name:
                return key_.id
        return 0

    def get_key_field(self, table_name, field_name):
        """ Get key field id for a given table and field. """
        if self.bfrt_info:
            return self.get_key_local(table_name, field_name)
        req = bfruntime_pb2.ReadRequest()
        req.client_id = self.client_id;
        req.target.device_id = self.device_id

        object_id = req.entities.add().object_id
        object_id.table_object.table_name = table_name
        object_id.table_object.key_field_name.field = field_name
        for rep in self.stub.Read(req):
            return rep.entities[0].object_id.id

    def get_key_name_local(self, table_name, field_id):
        table_obj = self.bfrt_info.table_dict[table_name]
        for field_name_, key_ in table_obj.key_dict.iteritems():
            if key_.id == field_id:
                return field_name_
        return ''

    def get_key_name(self, table_name, field_id):
        """ Get key field name for a given table and field id. """
        if self.bfrt_info:
            return self.get_key_name_local(table_name, field_id)
        assert False

    def swports(self, idx):
        if idx >= len(self._swports):
            self.fail("Index {} is out-of-bound of port map".format(idx))
            return None
        return self._swports[idx]

    # Helper functions to make writing BfRuntime PTF tests easier.
    DataField = namedtuple('data_field',
                           'name stream float_val str_val int_arr_val bool_arr_val bool_val')
    DataField.__new__.__defaults__ = (None, None, None, None, None, None, None)

    KeyField = namedtuple('key_field', 'name value mask prefix_len low high')
    KeyField.__new__.__defaults__ = (None, None, None, None, None, None)

    Target = namedtuple('target', 'device_id pipe_id direction prsr_id')
    Target.__new__.__defaults__ = (0, 0xffff, 0xff, 0xff)

    IpRandom = namedtuple('ip_random', 'ip prefix_len mask')
    MacRandom = namedtuple('mac_random', 'mac mask')

    def parseTableUsage(self, response, table_id_dict):
        '''
        table_id_dict is a dictionary of table_ids
        '''
        for rep in response:
            for entity in rep.entities:
                table_usage_response = entity.table_usage
                for table_id_query, usage_val in table_id_dict.iteritems():
                    if table_usage_response.table_id == table_id_query:
                        table_id_dict[
                            table_id_query] = table_usage_response.usage
                # Yielding here allows to iterate over more entities
                yield

    def parseKey(self, key, key_dict):
        for key_field in key.fields:
            key_dict[key_field.field_id] = {}
            if key_field.HasField("exact"):
                key_dict[key_field.field_id]["value"] = key_field.exact.value
            elif key_field.HasField("ternary"):
                key_dict[key_field.field_id]["value"] = key_field.ternary.value
                key_dict[key_field.field_id]["mask"] = key_field.ternary.mask
            elif key_field.HasField("lpm"):
                key_dict[key_field.field_id]["value"] = key_field.lpm.value
                key_dict[key_field.field_id][
                    "prefix_len"] = key_field.lpm.prefix_len
            elif key_field.HasField("range"):
                key_dict[key_field.field_id]["low"] = key_field.range.low
                key_dict[key_field.field_id]["high"] = key_field.range.high

    def parseDataField(self, field, data_dict):
        '''
        Parse a DataField
        '''
        data_dict.setdefault(field.field_id, [])
        if field.HasField("stream"):
            data_dict[field.field_id].append(field.stream)
        elif field.HasField("str_val"):
            data_dict[field.field_id].append(field.str_val)
        elif field.HasField("bool_val"):
            data_dict[field.field_id].append(field.bool_val)
        elif field.HasField("int_arr_val"):
            int_list = []
            for val in field.int_arr_val.val:
                int_list.append(val)
            data_dict[field.field_id].append(int_list)
        elif field.HasField("bool_arr_val"):
            bool_list = []
            for val in field.bool_arr_val.val:
                bool_list.append(val)
            data_dict[field.field_id].append(bool_list)
        elif field.HasField("container_arr_val"):
            # DataField objects could be encapsulated within a DataField object.
            # Parse the inner dataField objects here.
            for container in field.container_arr_val.container:
                data_fields_list = {}
                for val in container.val:
                    self.parseDataField(val, data_fields_list)
                data_dict[field.field_id].append(data_fields_list)
        else:
            data_dict[field.field_id].append(field.float_val)

    def parseData(self, data, data_dict):
        data_dict["action_id"] = [data.action_id]
        for field in data.fields:
            self.parseDataField(field, data_dict)

        """
        If only one element is present in the list created above,
        then make it into a value
        so now possible (key, values) can be
        (0, [True, False, True]) # for selector member status
        (1, [3,4,1,6]) #4 values in a list for 4 pipes in register read
        (2, 40) #A uint32_t value read
        .
        .
        """
        for key, val in data_dict.iteritems():
            if (len(val) == 1):
                data_dict[key] = data_dict[key][0]

    def parseEntryGetResponse(self, response, key_dict=None):
        for rep in response:
            for entity in rep.entities:
                data_dict = {}
                key = entity.table_entry.key
                if not entity.table_entry.is_default_entry:
                    if (key_dict is not None):
                        self.parseKey(key, key_dict)
                data = entity.table_entry.data
                self.parseData(data, data_dict)

                if entity.table_entry.is_default_entry:
                    data_dict["is_default_entry"] = True
                # Yielding here allows to iterate over more entities
                yield data_dict

    def set_table_key(self, table, key_fields, table_name):
        """ Sets the key for a bfn::TableEntry object
            @param table : bfn::TableEntry object.
            @param key_fields: List of (name, value, [mask]) tuples.
        """
        if table is None:
            logger.warning("Invalid TableEntry object.")
            return

        for field in key_fields:
            field_id = self.get_key_field(table_name, field.name)
            if field_id is None:
                logger.error("Data key %s not found.", field.name)
            key_field = table.key.fields.add()
            key_field.field_id = field_id
            if field.mask is not None:
                key_field.ternary.value = field.value
                key_field.ternary.mask = field.mask
            elif field.prefix_len is not None:
                key_field.lpm.value = field.value
                key_field.lpm.prefix_len = field.prefix_len
            elif field.low is not None or field.high is not None:
                key_field.range.low = field.low
                key_field.range.high = field.high
            else:
                key_field.exact.value = field.value

    def set_table_data(self, table, action, data_fields, table_name):
        """ Sets the data for a bfn::TableEntry object
            @param table : bfn::TableEntry object.
            @param ation : Name of the action
            @param data_fields: List of (name, value) tuples.
        """
        if action is not None:
            table.data.action_id = self.get_action(table_name, action)

        if data_fields is not None:
            for field in data_fields:
                data_field = table.data.fields.add()
                data_field.field_id = self.get_data_field(table_name, action,
                                                          field.name)
                if field.stream is not None:
                    data_field.stream = field.stream
                elif field.float_val is not None:
                    data_field.float_val = field.float_val
                elif field.str_val is not None:
                    data_field.str_val = field.str_val
                elif field.bool_val is not None:
                    data_field.bool_val = field.bool_val
                elif field.int_arr_val is not None:
                    data_field.int_arr_val.val.extend(field.int_arr_val)
                elif field.bool_arr_val is not None:
                    data_field.bool_arr_val.val.extend(field.bool_arr_val)

    def cpy_target(self, req, target_src):
        req.target.device_id = target_src.device_id
        req.target.pipe_id = target_src.pipe_id
        req.target.direction = target_src.direction
        req.target.prsr_id = target_src.prsr_id

    def apply_table_operations(self, target, table_name, table_op):
        """ Apply table operations
            @param target : target device
            @param table_name : Table name.
            @param table_op : table operations to send
        """
        if self.get_table(table_name) is None:
            logger.warning("Table %s not found", table_name)
            return

        req = bfruntime_pb2.WriteRequest()
        self.cpy_target(req, target)

        update = req.updates.add()
        update.type = bfruntime_pb2.Update.INSERT

        table_operation = update.entity.table_operation
        table_operation.table_id = self.get_table(table_name)
        table_operation.table_operations_type = table_op
        return self.write(req)

    def entry_write_req_make(self, req, table_name,
                             key_fields=[], action_names=[], data_fields=[],
                             update_type=bfruntime_pb2.Update.INSERT,
                             modify_inc_type=None):
        if self.get_table(table_name) is None:
            logger.warning("Table %s not found", table_name)
            return

        if key_fields is not None and action_names is not None and data_fields is not None:
            assert (len(key_fields) == len(action_names) == len(data_fields));
        for idx in range(len(key_fields)):
            update = req.updates.add()
            update.type = update_type
            table_entry = update.entity.table_entry
            table_entry.table_id = self.get_table(table_name)
            table_entry.is_default_entry = False
            if modify_inc_type != None:
                table_entry.table_mod_inc_flag.type = modify_inc_type

            if key_fields is not None and key_fields[idx] is not None:
                self.set_table_key(table_entry, key_fields[idx], table_name)
            if action_names is not None and data_fields is not None:
                self.set_table_data(table_entry, action_names[idx],
                                    data_fields[idx], table_name)
        return req

    def insert_table_entry(self, target, table_name,
                           key_fields=None, action_name=None, data_fields=[]):
        """ Insert a new table entry
            @param target : target device
            @param table_name : Table name.
            @param key_fields : List of (name, value, [mask]) tuples.
            @param action_name : Action name.
            @param data_fields : List of (name, value) tuples.
        """

        req = bfruntime_pb2.WriteRequest()
        self.cpy_target(req, target)

        return self.write(
            self.entry_write_req_make(req, table_name, [key_fields],
                                      [action_name], [data_fields],
                                      bfruntime_pb2.Update.INSERT))

    def insert_table_entry_performance(self, target, table_name,
                                       key_fields=[], action_names=[],
                                       data_fields=[]):
        """ Insert a new table entry
            @param target : target device
            @param table_name : Table name.
            @param key_fields : List of (List of (name, value, [mask]) tuples).
            @param action_name : List of Action names.
            @param data_fields : List of (List of (name, value) tuples).
        """
        # TODO: This is a temporary function which takes in a list of keyfields, actionnames
        #       and datafields. Moving forward when we restructure this client, we should
        #       remove this API and make insert_table_entry take in a list of all the
        #       aforementioned things
        assert (len(key_fields) == len(action_names) == len(data_fields));

        req = bfruntime_pb2.WriteRequest()
        req.client_id = self.client_id
        self.cpy_target(req, target)

        try:
            self.stub.Write(
                self.entry_write_req_make(req, table_name, key_fields,
                                          action_names, data_fields,
                                          bfruntime_pb2.Update.INSERT))
        except grpc.RpcError as e:
            status_code = e.code()
            if status_code != grpc.StatusCode.UNKNOWN:
                logger.info(
                    "The error code returned by the server for Performace test is not UNKNOWN, which indicates some error might have occured while trying to add the entries")
                printGrpcError(e)
                raise e
            else:
                # Retrieve the performace rate (entries per second) encoded in the details
                error_details = e.details()
                error_details_list = error_details.split()
                rate = float(error_details_list.pop())
                return rate

    def modify_table_entry(self, target, table_name,
                           key_fields=None, action_name=None,
                           data_fields=None):
        """ Modify a table entry
            @param target : target device
            @param table_name : Table name.
            @param key_fields : List of (name, value, [mask]) tuples.
            @param action_name : Action name.
            @param data_fields : List of (name, value) tuples.
        """

        req = bfruntime_pb2.WriteRequest()
        self.cpy_target(req, target)

        return self.write(
            self.entry_write_req_make(req, table_name, [key_fields],
                                      [action_name], [data_fields],
                                      bfruntime_pb2.Update.MODIFY))

    def modify_inc_table_entry(self, target, table_name,
                               key_fields=None, action_name=None,
                               data_fields=None,
                               modify_inc_type=bfruntime_pb2.TableModIncFlag.MOD_INC_ADD):
        """ Modify a table entry
            @param target : target device
            @param table_name : Table name.
            @param key_fields : List of (name, value, [mask]) tuples.
            @param action_name : Action name.
            @param data_fields : List of (name, value) tuples.
        """

        req = bfruntime_pb2.WriteRequest()
        self.cpy_target(req, target)

        return self.write(
            self.entry_write_req_make(req, table_name, [key_fields],
                                      [action_name], [data_fields],
                                      bfruntime_pb2.Update.MODIFY_INC,
                                      modify_inc_type))

    def set_entry_scope_table_attribute(self, target, table_name,
                                        config_gress_scope=False,
                                        predefined_gress_scope_val=bfruntime_pb2.Mode.ALL,
                                        config_pipe_scope=True,
                                        predefined_pipe_scope=True,
                                        predefined_pipe_scope_val=bfruntime_pb2.Mode.ALL,
                                        user_defined_pipe_scope_val=0xffff,
                                        pipe_scope_args=0xff,
                                        config_prsr_scope=False,
                                        predefined_prsr_scope_val=bfruntime_pb2.Mode.ALL,
                                        prsr_scope_args=0xff):
        """ Set Entry Scope for the table
            @param target : target device
            @param table_name : Table name.
            @param config_gress_scope : configure gress_scope for the table
            @param predefined_gress_scope_val : (Optional) Only valid when config_gress_scope=True
            @param config_pipe_scope : configure pipe_scope for the table
            @param predefined_pipe_scope : (Optional) Only valid when config_pipe_scope=True, configure pipe_scope to predefined scope or user_defined one
            @param predefined_pipe_scope_val : (Optional) Only valid when config_pipe_scope=True
            @param user_defined_pipe_scope_val : (Optional) Only valid when pipe_scope type is user defined
            @param pipe_scope_args : (Optional) Only valid when config_pipe_scope=True
            @param config_prsr_scope : configure prsr_scope for the table
            @param predefined_prsr_scope_val : (Optional) Only valid when config_prsr_scope=True
            @param prsr_scope_args : (Optional) Only valid when config_prsr_scope=True
        """
        if self.get_table(table_name) is None:
            logger.warning("Table %s not found", table_name)
            return
        req = bfruntime_pb2.WriteRequest()
        self.cpy_target(req, target)

        update = req.updates.add()
        update.type = bfruntime_pb2.Update.INSERT

        table_attribute = update.entity.table_attribute
        table_attribute.table_id = self.get_table(table_name)

        if config_gress_scope == True:
            table_attribute.entry_scope.gress_scope.predef = predefined_gress_scope_val
        if config_pipe_scope == True:
            if predefined_pipe_scope == True:
                table_attribute.entry_scope.pipe_scope.predef = predefined_pipe_scope_val
            else:
                table_attribute.entry_scope.pipe_scope.user_defined = user_defined_pipe_scope_val
            table_attribute.entry_scope.pipe_scope.args = pipe_scope_args
        if config_prsr_scope == True:
            table_attribute.entry_scope.prsr_scope.predef = predefined_prsr_scope_val
            table_attribute.entry_scope.prsr_scope.args = prsr_scope_args

        return self.write(req)

    def set_idle_time_table_attribute(self, target, table_name, enable=False,
                                      idle_table_mode=bfruntime_pb2.IdleTable.IDLE_TABLE_NOTIFY_MODE,
                                      ttl_query_interval=5000, max_ttl=3600000,
                                      min_ttl=1000):
        """ Set Entry Scope for the table
            @param target : target device
            @param table_name : Table name.
            @param idle_table_mode : Mode of the idle table (POLL_MODE or NOTIFY_MODE)
            @param ttl_query_length : Minimum query interval
            @param max_ttl : Max TTL any entry in this table can have in msecs
            @param min_ttl : Min TTL any entry in this table can have in msecs
        """
        if self.get_table(table_name) is None:
            logger.warning("Table %s not found", table_name)
            return
        req = bfruntime_pb2.WriteRequest()
        self.cpy_target(req, target)

        update = req.updates.add()
        update.type = bfruntime_pb2.Update.INSERT

        table_attribute = update.entity.table_attribute
        table_attribute.table_id = self.get_table(table_name)

        table_attribute.idle_table.enable = enable
        table_attribute.idle_table.idle_table_mode = idle_table_mode
        table_attribute.idle_table.ttl_query_interval = ttl_query_interval
        table_attribute.idle_table.max_ttl = max_ttl
        table_attribute.idle_table.min_ttl = min_ttl

        return self.write(req)

    def set_port_status_change_attribute(self, target, table_name,
                                         enable=False):
        """ Set port status change notification for the table
            @param target : target device
            @param table_name : Table name.
            @param enable : notification enable
        """
        if self.get_table(table_name) is None:
            logger.warning("Table %s not found", table_name)
            return
        req = bfruntime_pb2.WriteRequest()
        self.cpy_target(req, target)

        update = req.updates.add()
        update.type = bfruntime_pb2.Update.INSERT

        table_attribute = update.entity.table_attribute
        table_attribute.table_id = self.get_table(table_name)

        table_attribute.port_status_notify.enable = enable
        return self.write(req)

    def set_port_stat_poll_intvl(self, target, table_name, intvl):
        """ Set port stat poll interval(ms) for the table
            @param target : target device
            @param table_name : Table name.
            @param intvl : time interval, millisecond
        """
        if self.get_table(table_name) is None:
            logger.warning("Table %s not found", table_name)
            return
        req = bfruntime_pb2.WriteRequest()
        self.cpy_target(req, target)

        update = req.updates.add()
        update.type = bfruntime_pb2.Update.INSERT

        table_attribute = update.entity.table_attribute
        table_attribute.table_id = self.get_table(table_name)

        table_attribute.intvl_ms.intvl_val = intvl
        return self.write(req)

    def set_pre_device_config_attribute(self, target, table_name,
                                        global_rid=None,
                                        port_protection_enable=None,
                                        fast_failover_enable=None,
                                        max_nodes_before_yield=None,
                                        max_node_threshold_node_count=None,
                                        max_node_threshold_port_lag_count=None):
        """ Set device config for the PRE MGID table
            @param target : Target device
            @param table_name : Table name.
            @param global_rid : Global RID value
            @param port_protection_enable : True of False to denote port protection enable/disable
            @param fast_failover_enable : True of False to denote fast failover enable/disable
            @param max_nodes_before_yield : max nodes before yield count value
            @param max_node_threshold_node_count : max node threshold node count value
            @param max_node_threshold_port_lag_count : max node threshold port lag count value
        """
        if self.get_table(table_name) is None:
            logger.warning("Table %s not found", table_name)
            return
        req = bfruntime_pb2.WriteRequest()
        self.cpy_target(req, target)

        update = req.updates.add()
        update.type = bfruntime_pb2.Update.INSERT

        table_attribute = update.entity.table_attribute
        table_attribute.table_id = self.get_table(table_name)

        if global_rid != None:
            table_attribute.pre_device_config.pre_global_rid.global_rid = global_rid

        if port_protection_enable != None:
            table_attribute.pre_device_config.pre_port_protection.enable = port_protection_enable

        if fast_failover_enable != None:
            table_attribute.pre_device_config.pre_fast_failover.enable = fast_failover_enable

        if max_nodes_before_yield != None:
            table_attribute.pre_device_config.pre_max_nodes_before_yield.count = max_nodes_before_yield

        # Either both max_node_threshold_node_count and max_node_threshold_port_lag_count
        # should be present OR both should be absent
        if max_node_threshold_node_count != None and max_node_threshold_port_lag_count == None:
            assert False
        if max_node_threshold_node_count == None and max_node_threshold_port_lag_count != None:
            assert False

        if max_node_threshold_node_count != None:
            table_attribute.pre_device_config.pre_max_node_threshold.node_count = max_node_threshold_node_count
            table_attribute.pre_device_config.pre_max_node_threshold.port_lag_count = max_node_threshold_port_lag_count

        return self.write(req)

    def set_dyn_key_mask_table_attribute(self, target, table_name, key_fields):
        """ Set dynamic key mask for the exact match table
            @param target : target device
            @param table_name : Table name.
            @param key_fields List of (name, mask) tuples.
        """
        if self.get_table(table_name) is None:
            logger.warning("Table %s not found", table_name)
            return
        req = bfruntime_pb2.WriteRequest()
        self.cpy_target(req, target)

        update = req.updates.add()
        update.type = bfruntime_pb2.Update.INSERT

        table_attribute = update.entity.table_attribute
        table_attribute.table_id = self.get_table(table_name)
        for field in key_fields:
            field_id = self.get_key_field(table_name, field.name)
            if field_id is None:
                logger.error("Data key %s not found.", field.name)
            key_field = table_attribute.dyn_key_mask.fields.add()
            key_field.field_id = field_id
            key_field.mask = field.value;

        return self.write(req)

    def set_dyn_hashing_table_attribute(self, target, table_name, alg_hdl=0,
                                        seed=0):
        """ Set dynamic hashing attribute (algorithm_handler and seed) for the dynamic hashing table
            @param target : target device
            @param table_name : Table name.
            @param alg_hdl: algorithm handler
            @param seed: seed
        """
        if self.get_table(table_name) is None:
            logger.warning("Table %s not found", table_name)
            return
        req = bfruntime_pb2.WriteRequest()
        self.cpy_target(req, target)

        update = req.updates.add()
        update.type = bfruntime_pb2.Update.INSERT

        table_attribute = update.entity.table_attribute
        table_attribute.table_id = self.get_table(table_name)

        table_attribute.dyn_hashing.alg = alg_hdl;
        table_attribute.dyn_hashing.seed = seed;

        return self.write(req)

    def set_meter_bytecount_adjust_attribute(self, target, table_name,
                                             byte_count=0):
        """ Set meter bytecount adjust attribute for the meter table
            @param target : target device
            @param table_name : Table name.
            @param byte_count : number of adjust bytes
        """
        if self.get_table(table_name) is None:
            logger.warning("Table %s not found", table_name)
            return
        req = bfruntime_pb2.WriteRequest()
        self.cpy_target(req, target)

        update = req.updates.add()
        update.type = bfruntime_pb2.Update.INSERT

        table_attribute = update.entity.table_attribute
        table_attribute.table_id = self.get_table(table_name)

        table_attribute.byte_count_adj.byte_count_adjust = byte_count;

        return self.write(req)

    def get_table_entry(self, target, table_name,
                        key_fields, flag_dict, action_name=None,
                        data_field_name_list=None,
                        default_entry=False):
        """ Get a table entry
            @param target : target device
            @param table_name : Table name.
            @param key_fields : List of (name, value, [mask]) tuples.
            @param flag : dict of flags
            @param action_name : Action name.
            @param data_field_ids : List of field_names
        """
        if self.get_table(table_name) is None:
            logger.warning("Table %s not found", table_name)
            return

        req = bfruntime_pb2.ReadRequest()
        req.client_id = self.client_id;
        self.cpy_target(req, target)
        return self.read(
            self.entry_read_req_make(req, table_name, key_fields, flag_dict,
                                     action_name, data_field_name_list,
                                     default_entry))

    def entry_read_req_make(self, req, table_name, key_fields,
                            flag_dict, action_name=None,
                            data_field_name_list=None, default_entry=False):
        table_entry = req.entities.add().table_entry
        table_entry.table_id = self.get_table(table_name)
        table_entry.is_default_entry = default_entry

        for key, value in flag_dict.iteritems():
            if (key == "from_hw"):
                table_entry.table_read_flag.from_hw = value;

        if (key_fields):
            self.set_table_key(table_entry, key_fields, table_name)

        # We Do not care about values in the data_fields which we are constructing
        data_fields = [self.DataField(field_name, '') for field_name in
                       data_field_name_list or []]
        self.set_table_data(table_entry, action_name, data_fields, table_name)
        return req

    def get_table_usage(self, target, table_name):
        if self.get_table(table_name) is None:
            logger.warning("Table %s not found", table_name)
            return
        req = bfruntime_pb2.ReadRequest()
        req.client_id = self.client_id;
        self.cpy_target(req, target)

        table_usage = req.entities.add().table_usage
        table_usage.table_id = self.get_table(table_name)

        return self.read(req)

    def delete_table_entry_performance(self, target, table_name,
                                       key_fields=[]):
        """ Delete table entries
            @param target : target device
            @param table_name : Table name.
            @param key_fields : List of (List of (name, value, [mask]) tuples).
        """
        # TODO: This is a temporary function which takes in a list of keyfields, actionnames
        #       and datafields. Moving forward when we restructure this client, we should
        #       remove this API and make delete_table_entry take in a list of all the
        #       aforementioned things

        req = bfruntime_pb2.WriteRequest()
        req.client_id = self.client_id
        self.cpy_target(req, target)

        try:
            self.stub.Write(
                self.entry_write_req_make(req, table_name, key_fields,
                                          None, None,
                                          bfruntime_pb2.Update.DELETE))
        except grpc.RpcError as e:
            status_code = e.code()
            if status_code != grpc.StatusCode.UNKNOWN:
                logger.info(
                    "The error code returned by the server for Performace test is not UNKNOWN, which indicates some error might have occured while trying to delete the entries")
                printGrpcError(e)
                raise e
            else:
                # Retrieve the performace rate (entries per second) encoded in the details
                error_details = e.details()
                error_details_list = error_details.split()
                rate = float(error_details_list.pop())
                return rate

    def delete_table_entry(self, target, table_name, key_fields=None):
        """ Delete a table entry
            @param target : target device
            @param table : Table name.
            @param key_fields: List of (name, value, [mask]) tuples.
        """

        req = bfruntime_pb2.WriteRequest()
        self.cpy_target(req, target)

        return self.write(
            self.entry_write_req_make(req, table_name, [key_fields],
                                      [None], [None],
                                      bfruntime_pb2.Update.DELETE))

    def reset_table_default_entry(self, target, table_name):
        req = bfruntime_pb2.WriteRequest()
        self.cpy_target(req, target)
        update = req.updates.add()
        update.type = bfruntime_pb2.Update.DELETE
        table_entry = update.entity.table_entry
        table_entry.table_id = self.get_table(table_name)
        table_entry.is_default_entry = True
        return self.write(req)

    def modify_table_default_entry(self, target, table_name,
                                   action_name=None, data_fields=None):
        """ Add default entry
            @param target : target device
            @param table_name : Table name.
            @param action_name : Action name.
            @param data_fields : List of (name, value) tuples.
        """
        if self.get_table(table_name) is None:
            logger.warning("Table %s not found", table_name)
            return

        req = bfruntime_pb2.WriteRequest()
        self.cpy_target(req, target)

        update = req.updates.add()
        update.type = bfruntime_pb2.Update.MODIFY

        table_entry = update.entity.table_entry
        table_entry.table_id = self.get_table(table_name)
        table_entry.is_default_entry = True

        self.set_table_data(table_entry, action_name, data_fields, table_name)
        rep = self.write(req)

    def to_bytes(self, n, length):
        """ Conver integers to bytearray. """
        h = '%x' % n
        s = ('0' * (len(h) % 2) + h).zfill(length * 2).decode('hex')
        return s

    def ipv4_to_bytes(self, addr):
        """ Convert Ipv4 address to a bytearray. """
        val = map(lambda v: int(v), addr.split('.'))
        return "".join(chr(v) for v in val)

    def ipv6_to_bytes(self, addr):
        """ Convert Ipv6 address to a bytearray. """
        return socket.inet_pton(socket.AF_INET6, addr)

    def mac_to_bytes(self, addr):
        """ Covert Mac address to a bytearray. """
        val = map(lambda v: int(v, 16), addr.split(':'))
        return "".join(chr(v) for v in val)

    def generate_random_ip_list(self, num_entries, seed):
        """ Generate random, unique, non overalapping IP address/mask """
        unique_keys = {}
        ip_list = []
        i = 0
        random.seed(seed)
        duplicate = False
        min_mask_len = max(1, int(math.ceil(math.log(num_entries, 2))))
        while (i < num_entries):
            duplicate = False
            ip = "%d.%d.%d.%d" % (
                random.randint(1, 255), random.randint(0, 255),
                random.randint(0, 255), random.randint(0, 255))
            p_len = random.randint(min_mask_len, 32)
            # Check if the dst_ip, p_len is already present in the list
            ipAddrbytes = ip.split('.')
            ipnumber = (int(ipAddrbytes[0]) << 24) + (
                    int(ipAddrbytes[1]) << 16) + (
                               int(ipAddrbytes[2]) << 8) + int(
                ipAddrbytes[3])
            mask = 0xffffffff
            mask = (mask << (32 - p_len)) & (0xffffffff)
            if ipnumber & mask in unique_keys:
                continue
            for _, each in unique_keys.iteritems():
                each_ip = each[0]
                each_mask = each[1]
                if ipnumber & each_mask == each_ip & each_mask:
                    duplicate = True
                    break
            if duplicate:
                continue
            duplicate = False
            unique_keys[ipnumber & mask] = (ipnumber, mask)
            ip_list.append(self.IpRandom(ip, p_len, mask))
            i += 1
        return ip_list

    def generate_random_mac_list(self, num_entries, seed):
        """ Generate random, unique, non overalapping MAC address/mask """
        unique_keys = {}
        mac_list = []
        i = 0
        random.seed(seed)
        duplicate = False
        while (i < num_entries):
            duplicate = False
            mac = "%02x:%02x:%02x:%02x:%02x:%02x" % (
                random.randint(0, 255), random.randint(0, 255),
                random.randint(0, 255), random.randint(0, 255),
                random.randint(0, 255), random.randint(0, 255))
            mask = "%02x:%02x:%02x:%02x:%02x:%02x" % (
                random.randint(0, 255), random.randint(0, 255),
                random.randint(0, 255), random.randint(0, 255),
                random.randint(0, 255), random.randint(0, 255))
            # Check if the dst_ip, p_len is already present in the list
            macAddrBytes = mac.split(':')
            macMaskBytes = mask.split(":")

            macnumber = 0
            masknumber = 0

            for x in range(len(macAddrBytes)):
                macnumber = macnumber | int(macAddrBytes[x], 16) << (
                        8 * (len(macAddrBytes) - x - 1))
                masknumber = masknumber | int(macAddrBytes[x], 16) << (
                        8 * (len(macAddrBytes) - x - 1))

            if macnumber & masknumber in unique_keys:
                continue

            for _, each in unique_keys.iteritems():
                each_mac = each[0]
                each_mask = each[1]
                if macnumber & each_mask == each_mac & each_mask:
                    duplicate = True
                    break
            if duplicate:
                continue
            duplicate = False

            unique_keys[macnumber & masknumber] = (macnumber, masknumber)
            mac_list.append(self.MacRandom(mac, mask))
            i += 1
        return mac_list
