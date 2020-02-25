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
# Unit tests for convert.py
import logging
import unittest

import ipaddress

from trans_sec.utils import convert


class ConvertTests(unittest.TestCase):
    """
    Unit tests for utility functions in convert.py
    """

    def test_convert(self):
        """
        Tests convert.py
        """
        logging.basicConfig(level=logging.DEBUG)
        mac = "aa:bb:cc:dd:ee:ff"
        enc_mac = convert.encode_mac(mac)
        self.assertEquals('\xaa\xbb\xcc\xdd\xee\xff', enc_mac)
        dec_mac = convert.decode_mac(enc_mac)
        self.assertEquals(mac, dec_mac)

        ip = "10.0.0.1"
        enc_ip = convert.encode_ipv4(ip)
        self.assertEquals(enc_ip, '\x0a\x00\x00\x01')
        dec_ip = convert.decode_ipv4(enc_ip)
        self.assertEquals(ip, dec_ip)

        num = 1337
        byte_len = 5
        enc_num = convert.encode_num(num, byte_len * 8)
        self.assertEquals(enc_num, '\x00\x00\x00\x05\x39')
        dec_num = convert.decode_num(enc_num)
        self.assertEquals(num, dec_num)

        self.assertTrue(convert.matches_ipv4('10.0.0.1'))
        self.assertFalse(convert.matches_ipv4('10.0.0.1.5'))
        self.assertFalse(convert.matches_ipv4('1000.0.0.1'))
        self.assertFalse(convert.matches_ipv4('10001'))

        ipv6 = '0000:0000:0000:0000:0000:0001:0001:0002'
        enc_ipv6 = convert.encode_ipv6(ipv6)
        self.assertTrue(convert.matches_ipv6(ipv6))
        self.assertTrue(convert.encode(ipv6, 128), enc_ipv6)
        dec_ipv6 = convert.decode_ipv6(enc_ipv6)
        ipv6_addr = ipaddress.ip_address(unicode(ipv6))
        self.assertEquals(str(ipv6_addr), dec_ipv6)

        ipv6b = '0:0:0:0:0:1:1:2'
        enc_ipv6b = convert.encode_ipv6(ipv6b)
        self.assertTrue(convert.matches_ipv6(ipv6b))
        self.assertTrue(convert.encode(ipv6b, 128), enc_ipv6b)
        dec_ipv6b = convert.decode_ipv6(enc_ipv6b)
        ipv6b_addr = ipaddress.ip_address(unicode(ipv6b))
        self.assertEquals(str(ipv6b_addr), dec_ipv6b)

        self.assertEquals(convert.encode(mac, 6 * 8), enc_mac)
        self.assertEquals(convert.encode(ip, 4 * 8), enc_ip)
        self.assertEquals(convert.encode(num, 5 * 8), enc_num)
        self.assertEquals(convert.encode((num,), 5 * 8), enc_num)
        self.assertEquals(convert.encode([num], 5 * 8), enc_num)

        num = 256
        try:
            convert.encode_num(num, 8)
            self.fail('Exception expected here')
        except SyntaxError:
            pass
