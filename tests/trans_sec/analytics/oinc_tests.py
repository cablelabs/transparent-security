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

import mock
from scapy.all import get_if_hwaddr
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from trans_sec.analytics.oinc import SimpleAE
from trans_sec.packet.inspect_layer import GatewayINTInspect
from trans_sec.utils.http_session import HttpSession

# noinspection PyCompatibility

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)

logger = logging.getLogger('oinc_tests')


class SimpleAETests(unittest.TestCase):
    """
    Unit tests for the class SimpleAE
    """

    def setUp(self):
        self.ae = SimpleAE(mock.Mock(HttpSession), packet_count=20,
                           sample_interval=2)

    def test_process_single_udp_packet(self):
        """
        Tests to ensure that a single packet is handled without Error
        note: only testing via the handle_packet() API which would be called by
              by the scapy sniffer thread
        :return:
        """
        pkt = (Ether(src=get_if_hwaddr('lo'), dst='ff:ff:ff:ff:ff:ff') /
               GatewayINTInspect() /
               IP(dst='localhost', src='localhost') /
               UDP(dport=1234, sport=1234) /
               'hello')
        self.ae.handle_packet(pkt)

    def test_start_one_attack(self):
        """
        Tests to ensure that one attack has been triggered
        :return:
        """
        pkt = Ether(src=get_if_hwaddr('lo'), dst='ff:ff:ff:ff:ff:ff')
        pkt = (pkt /
               GatewayINTInspect() /
               IP(dst='localhost', src='localhost') /
               UDP(dport=1234, sport=1234) /
               'hello')

        for index in range(0, self.ae.packet_count + 1):
            ret_val = self.ae.handle_packet(pkt)
            if index < self.ae.packet_count:
                self.assertFalse(ret_val)
            else:
                self.assertTrue(ret_val)

    def test_start_two_attacks(self):
        """
        Tests to ensure that one attack has been triggered
        :return:
        """
        pkt1 = (Ether(src=get_if_hwaddr('lo'), dst='ff:ff:ff:ff:ff:ff') /
                GatewayINTInspect(srcAddr='ff:ff:ff:ff:ff:ff') /
                IP(dst='localhost', src='localhost') /
                UDP(dport=1234, sport=1234) /
                'hello')

        pkt2 = (Ether(src=get_if_hwaddr('lo'), dst='ff:ff:ff:ff:ff:ff') /
                GatewayINTInspect(srcAddr='ff:ff:ff:ff:ff:aa') /
                IP(dst='localhost', src='localhost') /
                UDP(dport=1234, sport=1234) /
                'hello')

        for index in range(0, self.ae.packet_count + 1):
            logger.info('Iteration #%s', index)
            ret_val1 = self.ae.handle_packet(pkt1)
            ret_val2 = self.ae.handle_packet(pkt2)
            if index < self.ae.packet_count:
                self.assertFalse(ret_val1)
                self.assertFalse(ret_val2)
            else:
                self.assertTrue(ret_val1)
                self.assertTrue(ret_val2)
