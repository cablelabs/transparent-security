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
# Unit tests for http_session.py
import logging
import sys
import time
import unittest
from random import randrange, randint

import ipaddress
import mock
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

from trans_sec import consts
from trans_sec.analytics import oinc
from trans_sec.analytics.oinc import SimpleAE
from trans_sec.packet.inspect_layer import (
    IntShim, IntMeta2, IntHeader, SourceIntMeta, IntMeta1, UdpInt,
    TelemetryReport, DropReport)
from trans_sec.utils import tps_utils
from trans_sec.utils.http_session import HttpSession

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

logger = logging.getLogger('oinc_tests')


class SimpleAETests(unittest.TestCase):
    """
    Unit tests for the class SimpleAE
    """

    def setUp(self):
        self.ae = SimpleAE(mock.Mock(HttpSession), packet_count=20,
                           sample_interval=2)
        self.sport = randrange(1000, 8000)
        self.dport = randrange(1000, 8000)
        self.ae_ip = '192.168.1.2'
        self.dst_ipv4 = '10.1.0.2'
        self.src_ipv4 = '10.1.0.6'
        self.dst_ipv6 = ipaddress.ip_address(
            '0000:0000:0000:0000:0000:0001:0000:0001')
        self.src_ipv4 = '10.2.0.1'
        self.src_ipv6 = ipaddress.ip_address(
            '0000:0000:0000:0000:0000:0002:0000:0001')
        self.dst_mac = rand_mac()
        self.src_mac = rand_mac()
        # self.orig_mac = rand_mac()
        self.orig_mac = '00:00:00:02:02:00'
        logger.info('Test sport - [%s] dport - [%s]', self.sport, self.dport)

        self.int_pkt_ipv4_udp = (
                Ether(src='00:00:00:00:01:01', dst=self.dst_mac) /
                IP(dst=self.dst_ipv4, src=self.src_ipv4,
                   proto=consts.UDP_PROTO) /
                UdpInt(dport=consts.UDP_INT_DST_PORT) /
                IntShim(length=9, next_proto=consts.UDP_PROTO) /
                IntHeader(meta_len=1) /
                IntMeta1(switch_id=3) /
                IntMeta2(switch_id=2) /
                SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
                UDP(dport=self.dport, sport=self.sport) /
                'hello transparent-security'
        )

        self.ipv4_hash = tps_utils.create_attack_hash(
            mac=self.orig_mac, port=self.dport, ip_addr=self.dst_ipv4,
            ipv6_addr='::')
        ip_len = (consts.IPV4_HDR_LEN + consts.UDP_INT_HDR_LEN
                  + consts.DRPT_LEN + consts.UDP_HDR_LEN
                  + consts.DRPT_PAYLOAD_LEN)
        udp_int_len = ip_len - consts.IPV4_HDR_LEN

        self.int_drop_rpt_ipv4_udp = (
            Ether(type=consts.IPV4_TYPE) /
            IP(dst=self.ae_ip, src=self.src_ipv4, len=ip_len,
               proto=consts.UDP_PROTO) /
            UdpInt(sport=consts.UDP_INT_SRC_PORT,
                   dport=consts.UDP_TRPT_DST_PORT,
                   len=udp_int_len) /
            DropReport(
                ver=consts.DRPT_VER,
                node_id=0,
                in_type=consts.DRPT_IN_TYPE,
                rpt_len=consts.DRPT_REP_LEN, md_len=consts.DRPT_MD_LEN,
                rep_md_bits=consts.DRPT_MD_BITS,
                domain_id=consts.TRPT_DOMAIN_ID,
                var_opt_bsmd=consts.DRPT_BS_MD,
                timestamp=int(time.time()),
                drop_count=5,
                drop_hash=self.ipv4_hash)
        )

        self.int_pkt_ipv4_tcp = (
                Ether(src='00:00:00:00:01:01', dst=self.dst_mac) /
                IP(dst=self.dst_ipv4, src=self.src_ipv4,
                   proto=consts.UDP_PROTO) /
                UdpInt(dport=consts.UDP_INT_DST_PORT) /
                IntShim(length=9, next_proto=consts.TCP_PROTO) /
                IntHeader(meta_len=1) /
                IntMeta1(switch_id=3) /
                IntMeta2(switch_id=2) /
                SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
                TCP(dport=self.dport, sport=self.sport) /
                'hello transparent-security'
        )

        self.int_pkt_ipv6_udp = (
            Ether(src='00:00:00:00:01:01', dst=self.dst_mac,
                  type=consts.IPV6_TYPE) /
            IPv6(dst=self.dst_ipv6,
                 src=self.src_ipv6,
                 nh=consts.UDP_PROTO) /
            UDP(dport=consts.UDP_INT_DST_PORT) /
            IntShim(length=9, next_proto=consts.UDP_PROTO) /
            IntHeader(meta_len=1) /
            IntMeta1(switch_id=3) /
            IntMeta2(switch_id=2) /
            SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
            UDP(dport=self.dport, sport=self.sport) /
            'hello transparent-security'
        )

        self.int_pkt_ipv6_tcp = (
            Ether(src='00:00:00:00:01:01', dst=self.dst_mac,
                  type=consts.IPV6_TYPE) /
            IPv6(dst=self.dst_ipv6,
                 src=self.src_ipv6,
                 nh=consts.UDP_PROTO) /
            UDP(dport=consts.UDP_INT_DST_PORT) /
            IntShim(length=9, next_proto=consts.TCP_PROTO) /
            IntHeader(meta_len=1) /
            IntMeta1(switch_id=3) /
            IntMeta2(switch_id=2) /
            SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
            TCP(dport=self.dport, sport=self.sport) /
            'hello transparent-security'
        )

        self.trpt_pkt_ipv4_out_ipv4_in_udp = (
                Ether(src=self.src_mac, dst=self.dst_mac) /
                IP(dst=self.dst_ipv4, src=self.src_ipv4,
                   proto=consts.UDP_PROTO) /
                UDP(sport=0, dport=consts.UDP_TRPT_DST_PORT,
                    # udp + telemetry header size
                    len=len(self.int_pkt_ipv4_udp) + 20 + 20) /
                TelemetryReport(domain_id=consts.TRPT_DOMAIN_ID) /
                self.int_pkt_ipv4_udp
        )

        self.trpt_pkt_ipv4_out_ipv6_in_udp = (
                Ether(src=self.src_mac, dst=self.dst_mac) /
                IP(dst=self.dst_ipv4, src=self.src_ipv4,
                   proto=consts.UDP_PROTO) /
                UDP(sport=0, dport=consts.UDP_TRPT_DST_PORT,
                    # udp + telemetry header size
                    len=len(self.int_pkt_ipv4_udp) + 20 + 20) /
                TelemetryReport(domain_id=consts.TRPT_DOMAIN_ID) /
                self.int_pkt_ipv6_udp
        )

        self.trpt_pkt_ipv4_out_ipv4_in_tcp = (
                Ether(src=self.src_mac, dst=self.dst_mac) /
                IP(dst=self.dst_ipv4, src=self.src_ipv4,
                   proto=consts.UDP_PROTO) /
                UDP(sport=0, dport=consts.UDP_TRPT_DST_PORT,
                    # udp + telemetry header size
                    len=len(self.int_pkt_ipv4_udp) + 20 + 20) /
                TelemetryReport(domain_id=consts.TRPT_DOMAIN_ID) /
                self.int_pkt_ipv4_tcp
        )

        self.trpt_pkt_ipv4_out_ipv6_in_tcp = (
                Ether(src=self.src_mac, dst=self.dst_mac) /
                IP(dst=self.dst_ipv4, src=self.src_ipv4,
                   proto=consts.UDP_PROTO) /
                UDP(sport=0, dport=consts.UDP_TRPT_DST_PORT,
                    # udp + telemetry header size
                    len=len(self.int_pkt_ipv4_udp) + 20 + 20) /
                TelemetryReport(domain_id=consts.TRPT_DOMAIN_ID) /
                self.int_pkt_ipv6_tcp
        )

    def test_extract_ipv4_udp_packet(self):
        """
        Tests to ensure that an IPv4 UDP single packet will be parsed properly
        """
        int_data = oinc.extract_int_data(self.int_pkt_ipv4_udp[Ether])
        self.assertEqual(self.orig_mac, int_data['devMac'])
        self.assertEqual(self.src_ipv4, int_data['devAddr'])
        self.assertEqual(self.dst_ipv4, int_data['dstAddr'])
        self.assertEqual(self.dport, int_data['dstPort'])
        self.assertEqual(consts.UDP_PROTO, int_data['protocol'])

    def test_extract_ipv4_udp_packet_trpt(self):
        """
        Tests to ensure that an IPv4 UDP single packet will be parsed properly
        """
        int_data = oinc.extract_trpt_data(
            self.trpt_pkt_ipv4_out_ipv4_in_udp[UDP])
        self.assertEqual(self.orig_mac, int_data['devMac'])
        self.assertEqual(self.src_ipv4, int_data['devAddr'])
        self.assertEqual(self.dst_ipv4, int_data['dstAddr'])
        self.assertEqual(self.dport, int_data['dstPort'])
        self.assertEqual(consts.UDP_PROTO, int_data['protocol'])

    def test_extract_ipv4_udp_packet_drpt(self):
        """
        Tests to ensure that an IPv4 UDP drop report will be parsed properly
        """
        hash_key, count = oinc.extract_drop_rpt(
            self.int_drop_rpt_ipv4_udp[UdpInt])
        self.assertEqual(self.ipv4_hash, hash_key)
        self.assertEqual(5, count)

    def test_extract_ipv4_tcp_packet(self):
        """
        Tests to ensure that an IPv4 UDP single packet will be parsed properly
        """
        int_data = oinc.extract_int_data(self.int_pkt_ipv4_tcp[Ether])
        self.assertEqual(self.orig_mac, int_data['devMac'])
        self.assertEqual(self.src_ipv4, int_data['devAddr'])
        self.assertEqual(self.dst_ipv4, int_data['dstAddr'])
        self.assertEqual(self.dport, int_data['dstPort'])
        self.assertEqual(consts.TCP_PROTO, int_data['protocol'])

    def test_extract_ipv4_tcp_packet_trpt(self):
        """
        Tests to ensure that an IPv4 UDP single packet will be parsed properly
        """
        logger.debug('Packet to test - [%s]',
                     self.trpt_pkt_ipv4_out_ipv4_in_tcp)
        int_data = oinc.extract_trpt_data(
            self.trpt_pkt_ipv4_out_ipv4_in_tcp[UDP])
        self.assertEqual(self.orig_mac, int_data['devMac'])
        self.assertEqual(self.src_ipv4, int_data['devAddr'])
        self.assertEqual(self.dst_ipv4, int_data['dstAddr'])
        self.assertEqual(self.dport, int_data['dstPort'])
        self.assertEqual(consts.TCP_PROTO, int_data['protocol'])

    def test_extract_ipv6_udp_packet(self):
        """
        Tests to ensure that an IPv4 UDP single packet will be parsed properly
        """
        int_data = oinc.extract_int_data(self.int_pkt_ipv6_udp[Ether])
        self.assertEqual(self.orig_mac, int_data['devMac'])
        self.assertEqual(str(self.src_ipv6), int_data['devAddr'])
        self.assertEqual(str(self.dst_ipv6), int_data['dstAddr'])
        self.assertEqual(self.dport, int_data['dstPort'])
        self.assertEqual(consts.UDP_PROTO, int_data['protocol'])

    def test_extract_ipv6_udp_packet_trpt(self):
        """
        Tests to ensure that an IPv6 UDP single packet will be parsed properly
        """
        int_data = oinc.extract_trpt_data(
            self.trpt_pkt_ipv4_out_ipv6_in_udp[UDP])
        self.assertEqual(self.orig_mac, int_data['devMac'])
        self.assertEqual(str(self.src_ipv6), int_data['devAddr'])
        self.assertEqual(str(self.dst_ipv6), int_data['dstAddr'])
        self.assertEqual(self.dport, int_data['dstPort'])
        self.assertEqual(consts.UDP_PROTO, int_data['protocol'])

    def test_extract_ipv6_tcp_packet(self):
        """
        Tests to ensure that an IPv6 TCP single packet will be parsed properly
        """
        int_data = oinc.extract_int_data(self.int_pkt_ipv6_tcp[Ether])
        self.assertEqual(self.orig_mac, int_data['devMac'])
        self.assertEqual(str(self.src_ipv6), int_data['devAddr'])
        self.assertEqual(str(self.dst_ipv6), int_data['dstAddr'])
        self.assertEqual(self.dport, int_data['dstPort'])
        self.assertEqual(consts.TCP_PROTO, int_data['protocol'])

    def test_extract_ipv6_tcp_packet_trpt(self):
        """
        Tests to ensure that an IPv6 TCP single packet will be parsed properly
        """
        int_data = oinc.extract_trpt_data(
            self.trpt_pkt_ipv4_out_ipv6_in_tcp[UDP])
        self.assertEqual(self.orig_mac, int_data['devMac'])
        self.assertEqual(str(self.src_ipv6), int_data['devAddr'])
        self.assertEqual(str(self.dst_ipv6), int_data['dstAddr'])
        self.assertEqual(self.dport, int_data['dstPort'])
        self.assertEqual(consts.TCP_PROTO, int_data['protocol'])

    def test_process_single_drop_rpt_packet(self):
        """
        Tests to ensure that an IPv4 UDP single packet is handled without Error
        note: only testing via the handle_packet() API which would be called by
              by the scapy sniffer thread
        :return:
        """
        self.assertFalse(self.ae.process_drop_rpt(self.int_pkt_ipv4_udp))

    def test_process_single_ipv4_udp_packet(self):
        """
        Tests to ensure that an IPv4 UDP single packet is handled without Error
        note: only testing via the handle_packet() API which would be called by
              by the scapy sniffer thread
        :return:
        """
        self.assertFalse(self.ae.process_packet(self.int_pkt_ipv4_udp))

    def test_process_single_ipv4_udp_packet_trpt(self):
        """
        Tests to ensure that an IPv4 UDP single packet is handled without Error
        note: only testing via the handle_packet() API which would be called by
              by the scapy sniffer thread
        :return:
        """
        self.assertFalse(
            self.ae.process_packet(self.trpt_pkt_ipv4_out_ipv4_in_udp))

    def test_process_single_ipv6_udp_packet(self):
        """
        Tests to ensure that an IPv6 UDP single packet is handled without Error
        note: only testing via the handle_packet() API which would be called by
              by the scapy sniffer thread
        :return:
        """
        self.ae.process_packet(self.int_pkt_ipv6_udp)

    def test_process_single_ipv6_udp_packet_trpt(self):
        """
        Tests to ensure that an IPv6 UDP single packet is handled without Error
        note: only testing via the handle_packet() API which would be called by
              by the scapy sniffer thread
        :return:
        """
        self.ae.process_packet(
            self.trpt_pkt_ipv4_out_ipv6_in_udp, consts.UDP_TRPT_DST_PORT)

    def test_process_single_ipv4_tcp_packet(self):
        """
        Tests to ensure that a single IPv4 TCP packet is handled without Error
        note: only testing via the handle_packet() API which would be called by
              by the scapy sniffer thread
        :return:
        """
        self.ae.process_packet(self.int_pkt_ipv4_tcp)

    def test_process_single_ipv4_tcp_packet_trpt(self):
        """
        Tests to ensure that a single IPv4 TCP packet is handled without Error
        note: only testing via the handle_packet() API which would be called by
              by the scapy sniffer thread
        :return:
        """
        self.ae.process_packet(
            self.trpt_pkt_ipv4_out_ipv4_in_tcp, consts.UDP_TRPT_DST_PORT)

    def test_process_single_ipv6_tcp_packet(self):
        """
        Tests to ensure that a single IPv6 TCP packet is handled without Error
        note: only testing via the handle_packet() API which would be called by
              by the scapy sniffer thread
        :return:
        """
        self.ae.process_packet(self.int_pkt_ipv6_tcp)

    def test_process_single_ipv6_tcp_packet_trpt(self):
        """
        Tests to ensure that a single IPv6 TCP packet is handled without Error
        note: only testing via the handle_packet() API which would be called by
              by the scapy sniffer thread
        :return:
        """
        self.ae.process_packet(
            self.trpt_pkt_ipv4_out_ipv6_in_tcp, consts.UDP_TRPT_DST_PORT)

    def test_start_one_ipv4_udp_attack(self):
        """
        Tests to ensure that one IPv4 UDP attack has been triggered
        :return:
        """
        for index in range(0, self.ae.packet_count + 1):
            logger.debug('Processing packet #%s', index)
            ret_val = self.ae.process_packet(self.int_pkt_ipv4_udp)
            if index < self.ae.packet_count:
                self.assertFalse(ret_val)
            else:
                self.assertTrue(ret_val)

    def test_start_one_ipv4_udp_attack_trpt(self):
        """
        Tests to ensure that one IPv4 UDP attack has been triggered
        :return:
        """
        for index in range(0, self.ae.packet_count + 1):
            logger.debug('Processing packet #%s', index)
            ret_val = self.ae.process_packet(
                self.trpt_pkt_ipv4_out_ipv4_in_udp, consts.UDP_TRPT_DST_PORT)
            if index < self.ae.packet_count:
                self.assertFalse(ret_val)
            else:
                self.assertTrue(ret_val)

    def test_ipv4_udp_proc_attack_and_drop(self):
        """
        Tests to ensure that one IPv4 UDP attack has been triggered and has
        released after processing several drop reports
        :return:
        """
        ret_val = False
        for i in range(0, self.ae.packet_count + 1):
            logger.debug('Processing packet #%s', i)
            ret_val = self.ae.process_packet(
                self.trpt_pkt_ipv4_out_ipv4_in_udp, consts.UDP_TRPT_DST_PORT)
            if i < self.ae.packet_count:
                self.assertFalse(ret_val)
            else:
                self.assertTrue(ret_val)

        # Ensure didn't loop again with False
        self.assertTrue(ret_val)

        drop_ret = False
        for j in range(0, 4):
            drop_ret = self.ae.process_drop_rpt(self.int_drop_rpt_ipv4_udp)
            if j < 3:
                self.assertFalse(drop_ret)
            else:
                self.assertTrue(drop_ret)

        # Ensure didn't loop again with False
        self.assertTrue(drop_ret)

        proc_ret = self.ae.process_packet(
            self.trpt_pkt_ipv4_out_ipv4_in_udp, consts.UDP_TRPT_DST_PORT)
        self.assertFalse(proc_ret)

    def test_start_one_ipv6_udp_attack(self):
        """
        Tests to ensure that one IPv6 UDP attack has been triggered
        :return:
        """
        ret_val = False
        for index in range(0, self.ae.packet_count + 1):
            logger.debug('Processing packet #%s', index)
            ret_val = self.ae.process_packet(self.int_pkt_ipv6_udp)
            if index < self.ae.packet_count:
                self.assertFalse(ret_val)
            else:
                self.assertTrue(ret_val)
        self.assertTrue(ret_val)

    def test_start_one_ipv6_udp_attack_trpt(self):
        """
        Tests to ensure that one IPv6 UDP attack has been triggered
        :return:
        """
        ret_val = False
        for index in range(0, self.ae.packet_count + 1):
            logger.debug('Processing packet #%s', index)
            ret_val = self.ae.process_packet(
                self.trpt_pkt_ipv4_out_ipv6_in_udp, consts.UDP_TRPT_DST_PORT)
            if index < self.ae.packet_count:
                self.assertFalse(ret_val)
            else:
                self.assertTrue(ret_val)
        self.assertTrue(ret_val)

    def test_start_one_ipv4_tcp_attack(self):
        """
        Tests to ensure that one IPv4 TCP attack has been triggered
        :return:
        """
        for index in range(0, self.ae.packet_count + 1):
            logger.debug('Processing packet #%s', index)
            ret_val = self.ae.process_packet(self.int_pkt_ipv4_tcp)
            if index < self.ae.packet_count:
                self.assertFalse(ret_val)
            else:
                self.assertTrue(ret_val)

    def test_start_one_ipv4_tcp_attack_trpt(self):
        """
        Tests to ensure that one IPv4 TCP attack has been triggered
        :return:
        """
        ret_val = False
        for index in range(0, self.ae.packet_count + 1):
            logger.debug('Processing packet #%s', index)
            ret_val = self.ae.process_packet(
                self.trpt_pkt_ipv4_out_ipv4_in_tcp, consts.UDP_TRPT_DST_PORT)
            if index < self.ae.packet_count:
                self.assertFalse(ret_val)
            else:
                self.assertTrue(ret_val)

        self.assertTrue(ret_val)

    def test_start_one_ipv6_tcp_attack(self):
        """
        Tests to ensure that one IPv6 TCP attack has been triggered
        :return:
        """
        ret_val = False
        for index in range(0, self.ae.packet_count + 1):
            logger.debug('Processing packet #%s', index)
            ret_val = self.ae.process_packet(self.int_pkt_ipv6_tcp)
            if index < self.ae.packet_count:
                self.assertFalse(ret_val)
            else:
                self.assertTrue(ret_val)
        self.assertTrue(ret_val)

    def test_start_one_ipv6_tcp_attack_trpt(self):
        """
        Tests to ensure that one IPv6 TCP attack has been triggered
        :return:
        """
        ret_val = False
        for index in range(0, self.ae.packet_count + 1):
            logger.debug('Processing packet #%s', index)
            ret_val = self.ae.process_packet(
                self.trpt_pkt_ipv4_out_ipv6_in_tcp, consts.UDP_TRPT_DST_PORT)
            if index < self.ae.packet_count:
                self.assertFalse(ret_val)
            else:
                self.assertTrue(ret_val)
        self.assertTrue(ret_val)

    def test_start_two_ipv4_udp_attacks(self):
        """
        Tests to ensure that two IPv4 UDP attacks have been triggered
        :return:
        """
        pkt1 = (Ether(src='00:00:00:00:01:01', dst=self.dst_mac) /
                IP(dst=self.dst_ipv4, src=self.src_ipv4,
                   proto=consts.UDP_PROTO) /
                UdpInt() /
                IntShim(length=9, next_proto=consts.UDP_PROTO) /
                IntHeader(meta_len=1) /
                IntMeta1(switch_id=3) /
                IntMeta2(switch_id=2) /
                SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
                UDP(dport=self.dport, sport=self.sport) /
                'hello transparent-security')

        pkt2 = (Ether(src='00:00:00:00:01:01', dst=self.dst_mac) /
                IP(dst=self.dst_ipv4, src=self.src_ipv4,
                   proto=consts.UDP_PROTO) /
                UdpInt() /
                IntShim(length=9, next_proto=consts.UDP_PROTO) /
                IntHeader(meta_len=1) /
                IntMeta1(switch_id=3) /
                IntMeta2(switch_id=2) /
                SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
                UDP(dport=self.dport, sport=self.sport) /
                'hello transparent-security')

        for index in range(0, self.ae.packet_count):
            logger.info('Iteration #%s', index)
            ret_val1 = self.ae.process_packet(pkt1)
            ret_val2 = self.ae.process_packet(pkt2)
            logger.info('Checking index - [%s] - count - [%s]',
                        index, self.ae.packet_count)
            if index * 2 < self.ae.packet_count:
                logger.info('Expecting false - [%s]', ret_val1)
                self.assertFalse(ret_val1)
                self.assertFalse(ret_val2)
            else:
                logger.info('Expecting true - [%s]', ret_val1)
                self.assertTrue(ret_val1)
                self.assertTrue(ret_val2)

    def test_start_two_ipv6_udp_attacks(self):
        """
        Tests to ensure that two IPv6 UDP attacks have been triggered
        :return:
        """
        pkt1 = (Ether(src='00:00:00:00:01:01', dst=self.dst_mac,
                      type=consts.IPV6_TYPE) /
                IPv6(dst=self.dst_ipv6,
                     src=self.src_ipv6,
                     nh=consts.UDP_PROTO) /
                UdpInt() /
                IntShim(length=9, next_proto=consts.UDP_PROTO) /
                IntHeader(meta_len=1) /
                IntMeta1(switch_id=3) /
                IntMeta2(switch_id=2) /
                SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
                UDP(dport=self.dport, sport=self.sport) /
                'hello transparent-security')

        pkt2 = (Ether(src='00:00:00:00:01:01', dst=self.dst_mac,
                      type=consts.IPV6_TYPE) /
                IPv6(dst=self.dst_ipv6,
                     src=self.src_ipv6,
                     nh=consts.UDP_PROTO) /
                UdpInt() /
                IntShim(length=9, next_proto=consts.UDP_PROTO) /
                IntHeader(meta_len=1) /
                IntMeta1(switch_id=3) /
                IntMeta2(switch_id=2) /
                SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
                UDP(dport=self.dport, sport=self.sport) /
                'hello transparent-security')

        for index in range(0, self.ae.packet_count):
            logger.info('Iteration #%s', index)
            ret_val1 = self.ae.process_packet(pkt1)
            ret_val2 = self.ae.process_packet(pkt2)
            logger.info('Checking index - [%s] - count - [%s]',
                        index, self.ae.packet_count)
            if index * 2 < self.ae.packet_count:
                logger.info('Expecting false - [%s]', ret_val1)
                self.assertFalse(ret_val1)
                self.assertFalse(ret_val2)
            else:
                logger.info('Expecting true - [%s]', ret_val1)
                self.assertTrue(ret_val1)
                self.assertTrue(ret_val2)

    def test_start_two_ipv4_tcp_attacks(self):
        """
        Tests to ensure that two IPv4 UDP attacks have been triggered
        :return:
        """
        pkt1 = (Ether(src='00:00:00:00:01:01', dst=self.dst_mac) /
                IP(dst=self.dst_ipv4, src=self.src_ipv4,
                   proto=consts.UDP_PROTO) /
                UdpInt() /
                IntShim(length=9, next_proto=consts.TCP_PROTO) /
                IntHeader(meta_len=1) /
                IntMeta1(switch_id=3) /
                IntMeta2(switch_id=2) /
                SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
                TCP(dport=self.dport, sport=self.sport) /
                'hello transparent-security')

        pkt2 = (Ether(src='00:00:00:00:01:01', dst=self.dst_mac) /
                IP(dst=self.dst_ipv4, src=self.src_ipv4,
                   proto=consts.UDP_PROTO) /
                UdpInt() /
                IntShim(length=9, next_proto=consts.TCP_PROTO) /
                IntHeader(meta_len=1) /
                IntMeta1(switch_id=3) /
                IntMeta2(switch_id=2) /
                SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
                TCP(dport=self.dport, sport=self.sport) /
                'hello transparent-security')

        for index in range(0, self.ae.packet_count):
            logger.info('Iteration #%s', index)
            ret_val1 = self.ae.process_packet(pkt1)
            ret_val2 = self.ae.process_packet(pkt2)
            logger.info('Checking index - [%s] - count - [%s]',
                        index, self.ae.packet_count)
            if index * 2 < self.ae.packet_count:
                logger.info('Expecting false - [%s]', ret_val1)
                self.assertFalse(ret_val1)
                self.assertFalse(ret_val2)
            else:
                logger.info('Expecting true - [%s]', ret_val1)
                self.assertTrue(ret_val1)
                self.assertTrue(ret_val2)

    def test_start_two_ipv6_tcp_attacks(self):
        """
        Tests to ensure that two IPv6 UDP attacks have been triggered
        :return:
        """
        pkt1 = (Ether(src='00:00:00:00:01:01', dst=self.dst_mac,
                      type=consts.IPV6_TYPE) /
                IPv6(dst=self.dst_ipv6,
                     src=self.src_ipv6,
                     nh=consts.UDP_PROTO) /
                UdpInt() /
                IntShim(length=9, next_proto=consts.TCP_PROTO) /
                IntHeader(meta_len=1) /
                IntMeta1(switch_id=3) /
                IntMeta2(switch_id=2) /
                SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
                TCP(dport=self.dport, sport=self.sport) /
                'hello transparent-security')

        pkt2 = (Ether(src='00:00:00:00:01:01', dst=self.dst_mac,
                      type=consts.IPV6_TYPE) /
                IPv6(dst=self.dst_ipv6,
                     src=self.src_ipv6,
                     nh=consts.UDP_PROTO) /
                UdpInt() /
                IntShim(length=9, next_proto=consts.TCP_PROTO) /
                IntHeader(meta_len=1) /
                IntMeta1(switch_id=3) /
                IntMeta2(switch_id=2) /
                SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
                TCP(dport=self.dport, sport=self.sport) /
                'hello transparent-security')

        for index in range(0, self.ae.packet_count):
            logger.info('Iteration #%s', index)
            ret_val1 = self.ae.process_packet(pkt1)
            ret_val2 = self.ae.process_packet(pkt2)
            logger.info('Checking index - [%s] - count - [%s]',
                        index, self.ae.packet_count)
            if index * 2 < self.ae.packet_count:
                logger.info('Expecting false - [%s]', ret_val1)
                self.assertFalse(ret_val1)
                self.assertFalse(ret_val2)
            else:
                logger.info('Expecting true - [%s]', ret_val1)
                self.assertTrue(ret_val1)
                self.assertTrue(ret_val2)


def rand_mac():
    return "%02x:%02x:%02x:%02x:%02x:%02x" % (
        randint(0, 255),
        randint(0, 255),
        randint(0, 255),
        randint(0, 255),
        randint(0, 255),
        randint(0, 255)
    )
