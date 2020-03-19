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
import unittest
from random import randrange, randint

import ipaddress
import mock
from scapy.all import get_if_hwaddr
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

import trans_sec.consts
from trans_sec.analytics import oinc
from trans_sec.analytics.oinc import SimpleAE
from trans_sec.packet.inspect_layer import (
    IntShim, IntMeta2, IntHeader, SourceIntMeta, IntMeta1, UdpInt)
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
        self.dst_ipv4 = '10.1.0.1'
        self.dst_ipv6 = ipaddress.ip_address(
            unicode('0000:0000:0000:0000:0000:0001:0000:0001'))
        self.src_ipv4 = '10.2.0.1'
        self.src_ipv6 = ipaddress.ip_address(
            unicode('0000:0000:0000:0000:0000:0002:0000:0001'))
        self.dst_mac = rand_mac()
        self.orig_mac = rand_mac()
        logger.info('Test sport - [%s] dport - [%s]', self.sport, self.dport)

    def test_extract_ipv4_udp_packet(self):
        """
        Tests to ensure that an IPv4 UDP single packet will be parsed properly
        """
        pkt = (Ether(src=get_if_hwaddr('lo'), dst=self.dst_mac) /
               IP(dst=self.dst_ipv4, src=self.src_ipv4,
                  proto=trans_sec.consts.UDP_PROTO) /
               UdpInt() /
               IntShim(length=9, next_proto=trans_sec.consts.UDP_PROTO) /
               IntHeader(meta_len=1) /
               IntMeta1(switch_id=3) /
               IntMeta2(switch_id=2) /
               SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
               UDP(dport=self.dport, sport=self.sport) /
               'hello transparent-security')
        int_data = oinc.extract_int_data(pkt)
        self.assertEqual(self.orig_mac, int_data['devMac'])
        self.assertEqual(self.src_ipv4, int_data['devAddr'])
        self.assertEqual(self.dst_ipv4, int_data['dstAddr'])
        self.assertEqual(self.dport, int_data['dstPort'])
        self.assertEqual(trans_sec.consts.UDP_PROTO, int_data['protocol'])
        self.assertEqual(len(pkt), int_data['packetLen'])

    def test_extract_ipv4_tcp_packet(self):
        """
        Tests to ensure that an IPv4 UDP single packet will be parsed properly
        """
        pkt = (Ether(src=get_if_hwaddr('lo'), dst=self.dst_mac) /
               IP(dst=self.dst_ipv4, src=self.src_ipv4,
                  proto=trans_sec.consts.UDP_PROTO) /
               UdpInt() /
               IntShim(length=9, next_proto=trans_sec.consts.TCP_PROTO) /
               IntHeader(meta_len=1) /
               IntMeta1(switch_id=3) /
               IntMeta2(switch_id=2) /
               SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
               TCP(dport=self.dport, sport=self.sport) /
               'hello transparent-security')
        int_data = oinc.extract_int_data(pkt)
        self.assertEqual(self.orig_mac, int_data['devMac'])
        self.assertEqual(self.src_ipv4, int_data['devAddr'])
        self.assertEqual(self.dst_ipv4, int_data['dstAddr'])
        self.assertEqual(self.dport, int_data['dstPort'])
        self.assertEqual(trans_sec.consts.TCP_PROTO, int_data['protocol'])
        self.assertEqual(len(pkt), int_data['packetLen'])

    def test_extract_ipv6_udp_packet(self):
        """
        Tests to ensure that an IPv6 UDP single packet will be parsed properly
        """
        pkt = (Ether(src=get_if_hwaddr('lo'), dst=self.dst_mac,
                     type=trans_sec.consts.IPV6_TYPE) /
               IPv6(dst=self.dst_ipv6,
                    src=self.src_ipv6,
                    nh=trans_sec.consts.UDP_PROTO) /
               UdpInt() /
               IntShim(length=9, next_proto=trans_sec.consts.UDP_PROTO) /
               IntHeader(meta_len=1) /
               IntMeta1(switch_id=3) /
               IntMeta2(switch_id=2) /
               SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
               UDP(dport=self.dport, sport=self.sport) /
               'hello transparent-security')
        logger.info('Packet - [%s]', len(pkt))

        int_data = oinc.extract_int_data(pkt)
        self.assertEqual(self.orig_mac, int_data['devMac'])
        self.assertEqual(str(self.src_ipv6), int_data['devAddr'])
        self.assertEqual(str(self.dst_ipv6), int_data['dstAddr'])
        self.assertEqual(self.dport, int_data['dstPort'])
        self.assertEqual(trans_sec.consts.UDP_PROTO, int_data['protocol'])
        self.assertEqual(len(pkt), int_data['packetLen'])

    def test_extract_ipv6_tcp_packet(self):
        """
        Tests to ensure that an IPv6 TCP single packet will be parsed properly
        """
        pkt = (Ether(src=get_if_hwaddr('lo'), dst=self.dst_mac,
                     type=trans_sec.consts.IPV6_TYPE) /
               IPv6(dst=self.dst_ipv6,
                    src=self.src_ipv6,
                    nh=trans_sec.consts.UDP_PROTO) /
               UdpInt() /
               IntShim(length=9, next_proto=trans_sec.consts.TCP_PROTO) /
               IntHeader(meta_len=1) /
               IntMeta1(switch_id=3) /
               IntMeta2(switch_id=2) /
               SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
               TCP(dport=self.dport, sport=self.sport) /
               'hello transparent-security')
        logger.info('Packet - [%s]', len(pkt))

        int_data = oinc.extract_int_data(pkt)
        self.assertEqual(self.orig_mac, int_data['devMac'])
        self.assertEqual(str(self.src_ipv6), int_data['devAddr'])
        self.assertEqual(str(self.dst_ipv6), int_data['dstAddr'])
        self.assertEqual(self.dport, int_data['dstPort'])
        self.assertEqual(trans_sec.consts.TCP_PROTO, int_data['protocol'])
        self.assertEqual(len(pkt), int_data['packetLen'])

    def test_process_single_ipv4_udp_packet(self):
        """
        Tests to ensure that an IPv4 UDP single packet is handled without Error
        note: only testing via the handle_packet() API which would be called by
              by the scapy sniffer thread
        :return:
        """
        pkt = (Ether(src=get_if_hwaddr('lo'), dst=self.dst_mac) /
               IP(dst=self.dst_ipv4, src=self.src_ipv4,
                  proto=trans_sec.consts.UDP_PROTO) /
               UdpInt() /
               IntShim(length=9, next_proto=trans_sec.consts.UDP_PROTO) /
               IntHeader(meta_len=1) /
               IntMeta1(switch_id=3) /
               IntMeta2(switch_id=2) /
               SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
               UDP(dport=self.dport, sport=self.sport) /
               'hello transparent-security')
        self.ae.process_packet(pkt)

    def test_process_single_ipv6_udp_packet(self):
        """
        Tests to ensure that an IPv6 UDP single packet is handled without Error
        note: only testing via the handle_packet() API which would be called by
              by the scapy sniffer thread
        :return:
        """
        pkt = (Ether(src=get_if_hwaddr('lo'), dst=self.dst_mac,
                     type=trans_sec.consts.IPV6_TYPE) /
               IPv6(dst=self.dst_ipv6,
                    src=self.src_ipv6,
                    nh=trans_sec.consts.UDP_PROTO) /
               UdpInt() /
               IntShim(length=9, next_proto=trans_sec.consts.UDP_PROTO) /
               IntHeader(meta_len=1) /
               IntMeta1(switch_id=3) /
               IntMeta2(switch_id=2) /
               SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
               UDP(dport=self.dport, sport=self.sport) /
               'hello transparent-security')
        logger.info('Packet - [%s]', len(pkt))
        self.ae.process_packet(pkt)

    def test_process_single_ipv4_tcp_packet(self):
        """
        Tests to ensure that a single IPv4 TCP packet is handled without Error
        note: only testing via the handle_packet() API which would be called by
              by the scapy sniffer thread
        :return:
        """
        pkt = (Ether(src=get_if_hwaddr('lo'), dst=self.dst_mac) /
               IP(dst=self.dst_ipv4, src=self.src_ipv4,
                  proto=trans_sec.consts.UDP_PROTO) /
               UdpInt() /
               IntShim(length=9, next_proto=trans_sec.consts.TCP_PROTO) /
               IntHeader(meta_len=1) /
               IntMeta1(switch_id=3) /
               IntMeta2(switch_id=2) /
               SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
               TCP(dport=self.dport, sport=self.dport) /
               'hello transparent-security')
        self.ae.process_packet(pkt)

    def test_process_single_ipv6_tcp_packet(self):
        """
        Tests to ensure that a single IPv6 TCP packet is handled without Error
        note: only testing via the handle_packet() API which would be called by
              by the scapy sniffer thread
        :return:
        """
        pkt = (Ether(src=get_if_hwaddr('lo'), dst=self.dst_mac,
                     type=trans_sec.consts.IPV6_TYPE) /
               IPv6(dst=self.dst_ipv6,
                    src=self.src_ipv6,
                    nh=trans_sec.consts.UDP_PROTO) /
               UdpInt() /
               IntShim(length=9, next_proto=trans_sec.consts.TCP_PROTO) /
               IntHeader(meta_len=1) /
               IntMeta1(switch_id=3) /
               IntMeta2(switch_id=2) /
               SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
               TCP(dport=self.dport, sport=self.sport) /
               'hello transparent-security')
        self.ae.process_packet(pkt)

    def test_start_one_ipv4_udp_attack(self):
        """
        Tests to ensure that one IPv4 UDP attack has been triggered
        :return:
        """
        pkt = (Ether(src=get_if_hwaddr('lo'), dst=self.dst_mac) /
               IP(dst=self.dst_ipv4, src=self.src_ipv4,
                  proto=trans_sec.consts.UDP_PROTO) /
               UdpInt() /
               IntShim(length=9, next_proto=trans_sec.consts.UDP_PROTO) /
               IntHeader(meta_len=1) /
               IntMeta1(switch_id=3) /
               IntMeta2(switch_id=2) /
               SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
               UDP(dport=self.dport, sport=self.sport) /
               'hello transparent-security')

        for index in range(0, self.ae.packet_count + 1):
            logger.debug('Processing packet #%s', index)
            ret_val = self.ae.process_packet(pkt)
            if index < self.ae.packet_count:
                self.assertFalse(ret_val)
            else:
                self.assertTrue(ret_val)

    def test_start_one_ipv6_udp_attack(self):
        """
        Tests to ensure that one IPv6 UDP attack has been triggered
        :return:
        """
        pkt = (Ether(src=get_if_hwaddr('lo'), dst=self.dst_mac,
                     type=trans_sec.consts.IPV6_TYPE) /
               IPv6(dst=self.dst_ipv6,
                    src=self.src_ipv6,
                    nh=trans_sec.consts.UDP_PROTO) /
               UdpInt() /
               IntShim(length=9, next_proto=trans_sec.consts.UDP_PROTO) /
               IntHeader(meta_len=1) /
               IntMeta1(switch_id=3) /
               IntMeta2(switch_id=2) /
               SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
               UDP(dport=self.dport, sport=self.sport) /
               'hello transparent-security')

        for index in range(0, self.ae.packet_count + 1):
            logger.debug('Processing packet #%s', index)
            ret_val = self.ae.process_packet(pkt)
            if index < self.ae.packet_count:
                self.assertFalse(ret_val)
            else:
                self.assertTrue(ret_val)

    def test_start_one_ipv4_tcp_attack(self):
        """
        Tests to ensure that one IPv4 TCP attack has been triggered
        :return:
        """
        pkt = (Ether(src=get_if_hwaddr('lo'), dst=self.dst_mac) /
               IP(dst=self.dst_ipv4, src=self.src_ipv4,
                  proto=trans_sec.consts.UDP_PROTO) /
               UdpInt() /
               IntShim(length=9, next_proto=trans_sec.consts.TCP_PROTO) /
               IntHeader(meta_len=1) /
               IntMeta1(switch_id=3) /
               IntMeta2(switch_id=2) /
               SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
               TCP(dport=self.dport, sport=self.sport) /
               'hello transparent-security')

        for index in range(0, self.ae.packet_count + 1):
            logger.debug('Processing packet #%s', index)
            ret_val = self.ae.process_packet(pkt)
            if index < self.ae.packet_count:
                self.assertFalse(ret_val)
            else:
                self.assertTrue(ret_val)

    def test_start_one_ipv6_tcp_attack(self):
        """
        Tests to ensure that one IPv6 TCP attack has been triggered
        :return:
        """
        pkt = (Ether(src=get_if_hwaddr('lo'), dst=self.dst_mac,
                     type=trans_sec.consts.IPV6_TYPE) /
               IPv6(dst=self.dst_ipv6,
                    src=self.src_ipv6,
                    nh=trans_sec.consts.UDP_PROTO) /
               UdpInt() /
               IntShim(length=9, next_proto=trans_sec.consts.TCP_PROTO) /
               IntHeader(meta_len=1) /
               IntMeta1(switch_id=3) /
               IntMeta2(switch_id=2) /
               SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
               TCP(dport=self.dport, sport=self.sport) /
               'hello transparent-security')

        for index in range(0, self.ae.packet_count + 1):
            logger.debug('Processing packet #%s', index)
            ret_val = self.ae.process_packet(pkt)
            if index < self.ae.packet_count:
                self.assertFalse(ret_val)
            else:
                self.assertTrue(ret_val)

    def test_start_two_ipv4_udp_attacks(self):
        """
        Tests to ensure that two IPv4 UDP attacks have been triggered
        :return:
        """
        pkt1 = (Ether(src=get_if_hwaddr('lo'), dst=self.dst_mac) /
                IP(dst=self.dst_ipv4, src=self.src_ipv4,
                   proto=trans_sec.consts.UDP_PROTO) /
                UdpInt() /
                IntShim(length=9, next_proto=trans_sec.consts.UDP_PROTO) /
                IntHeader(meta_len=1) /
                IntMeta1(switch_id=3) /
                IntMeta2(switch_id=2) /
                SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
                UDP(dport=self.dport, sport=self.sport) /
                'hello transparent-security')

        pkt2 = (Ether(src=get_if_hwaddr('lo'), dst=self.dst_mac) /
                IP(dst=self.dst_ipv4, src=self.src_ipv4,
                   proto=trans_sec.consts.UDP_PROTO) /
                UdpInt() /
                IntShim(length=9, next_proto=trans_sec.consts.UDP_PROTO) /
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
        pkt1 = (Ether(src=get_if_hwaddr('lo'), dst=self.dst_mac,
                      type=trans_sec.consts.IPV6_TYPE) /
                IPv6(dst=self.dst_ipv6,
                     src=self.src_ipv6,
                     nh=trans_sec.consts.UDP_PROTO) /
                UdpInt() /
                IntShim(length=9, next_proto=trans_sec.consts.UDP_PROTO) /
                IntHeader(meta_len=1) /
                IntMeta1(switch_id=3) /
                IntMeta2(switch_id=2) /
                SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
                UDP(dport=self.dport, sport=self.sport) /
                'hello transparent-security')

        pkt2 = (Ether(src=get_if_hwaddr('lo'), dst=self.dst_mac,
                      type=trans_sec.consts.IPV6_TYPE) /
                IPv6(dst=self.dst_ipv6,
                     src=self.src_ipv6,
                     nh=trans_sec.consts.UDP_PROTO) /
                UdpInt() /
                IntShim(length=9, next_proto=trans_sec.consts.UDP_PROTO) /
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
        pkt1 = (Ether(src=get_if_hwaddr('lo'), dst=self.dst_mac) /
                IP(dst=self.dst_ipv4, src=self.src_ipv4,
                   proto=trans_sec.consts.UDP_PROTO) /
                UdpInt() /
                IntShim(length=9, next_proto=trans_sec.consts.TCP_PROTO) /
                IntHeader(meta_len=1) /
                IntMeta1(switch_id=3) /
                IntMeta2(switch_id=2) /
                SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
                TCP(dport=self.dport, sport=self.sport) /
                'hello transparent-security')

        pkt2 = (Ether(src=get_if_hwaddr('lo'), dst=self.dst_mac) /
                IP(dst=self.dst_ipv4, src=self.src_ipv4,
                   proto=trans_sec.consts.UDP_PROTO) /
                UdpInt() /
                IntShim(length=9, next_proto=trans_sec.consts.TCP_PROTO) /
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
        pkt1 = (Ether(src=get_if_hwaddr('lo'), dst=self.dst_mac,
                      type=trans_sec.consts.IPV6_TYPE) /
                IPv6(dst=self.dst_ipv6,
                     src=self.src_ipv6,
                     nh=trans_sec.consts.UDP_PROTO) /
                UdpInt() /
                IntShim(length=9, next_proto=trans_sec.consts.TCP_PROTO) /
                IntHeader(meta_len=1) /
                IntMeta1(switch_id=3) /
                IntMeta2(switch_id=2) /
                SourceIntMeta(switch_id=1, orig_mac=self.orig_mac) /
                TCP(dport=self.dport, sport=self.sport) /
                'hello transparent-security')

        pkt2 = (Ether(src=get_if_hwaddr('lo'), dst=self.dst_mac,
                      type=trans_sec.consts.IPV6_TYPE) /
                IPv6(dst=self.dst_ipv6,
                     src=self.src_ipv6,
                     nh=trans_sec.consts.UDP_PROTO) /
                UdpInt() /
                IntShim(length=9, next_proto=trans_sec.consts.TCP_PROTO) /
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
