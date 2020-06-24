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
#
# Originally copied from:
#
# Copyright 2017-present Open Networking Foundation
#
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
#
import codecs
import logging
import math
import re
import socket

'''
This package contains several helper functions for encoding to and decoding
from byte strings:
- integers
- IPv4 address strings
- Ethernet address strings
'''

logger = logging.getLogger('convert')
mac_pattern = re.compile(r'^([\da-fA-F]{2}:){5}([\da-fA-F]{2})$')


def matches_mac(mac_addr_string):
    return mac_pattern.match(mac_addr_string) is not None


def encode_mac(mac_addr_string):
    hex_decoder = codecs.getdecoder('hex_codec')
    return hex_decoder(mac_addr_string.replace(':', ''))[0]


def decode_mac(encoded_mac_addr):
    logger.debug('decoding mac - [%s]', encoded_mac_addr)
    out = None
    mac_str = str(encoded_mac_addr)
    logger.debug('mac_str - [%s]', mac_str)
    tokens = str(mac_str).split('\\x')
    tokens.pop(0)
    for token in tokens:
        if not out:
            out = token
        else:
            out = out + ':' + token
    out = out.replace('/', '')
    out = out.replace('\'', '')
    logger.debug('decoded mac - [%s]', out)
    return out


def matches_ipv4(ip_addr_string):
    ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}(\d{1,3})$')
    return ipv4_pattern.match(ip_addr_string) is not None


def matches_ipv6(ipv6_addr_string):
    logger.debug('Matching string [%s] for IPv6', ipv6_addr_string)
    ipv6_pattern = re.compile(r'^([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}$')
    return ipv6_pattern.match(ipv6_addr_string) is not None


def encode_ipv4(ip_addr_string):
    logger.info('Encoding value - [%s] as IPv4', ip_addr_string)
    return socket.inet_aton(ip_addr_string)


def encode_ipv6(ip_addr_string):
    logger.info('Encoding value - [%s] as IPv6', ip_addr_string)
    return socket.inet_pton(socket.AF_INET6, ip_addr_string)


def decode_ipv4(encoded_ip_addr):
    return socket.inet_ntoa(encoded_ip_addr)


def decode_ipv6(encoded_ip_addr):
    return socket.inet_ntop(socket.AF_INET6, encoded_ip_addr)


def bitwidth_to_bytes(bitwidth):
    return int(math.ceil(bitwidth / 8.0))


def encode_num(number, bitwidth):
    logger.info('number to encode [%s] with width [%s]', number, bitwidth)
    bitwidth_bytes = bitwidth_to_bytes(bitwidth)
    num_str = '%x' % number
    if number >= 2 ** bitwidth:
        raise SyntaxError(
            "Number, %d, does not fit in %d bits" % (number, bitwidth))
    hex_decoder = codecs.getdecoder('hex_codec')
    return hex_decoder('0' * (bitwidth_bytes * 2 - len(num_str)) + num_str)[0]


def decode_num(encoded_number):
    logger.debug('hex number to decode - [%s]', encoded_number)
    out = None
    logger.debug('mac_str - [%s]', encoded_number)
    tokens = str(encoded_number).split('\\x')
    tokens.pop(0)
    for token in tokens:
        if not out:
            out = '0x' + token
        else:
            out = out + token
    out = out.replace('/', '')
    out = out.replace('\'', '')
    logger.debug('out for out_hex - [%s]', out)
    out_hex = int(out, 16)
    logger.debug('decoded number - [%s]', out_hex)
    return out_hex

    # logger.debug('Num to decode - [%s]', encoded_number)
    # joined_num = "".join(str(encoded_number).split()[::-1])
    # logger.debug('joined_num - [%s]', joined_num)
    # out = hex(joined_num)
    # return out
    # hex_decoder = codecs.getdecoder('hex_codec')
    # decoded = hex_decoder(encoded_number)
    # return int(decoded)


def encode(x, bitwidth):
    """
    Tries to infer the type of `x` and encode it
    """
    logger.info('Encoding - [%s] with - [%s]', x, bitwidth)
    bitwidth_bytes = bitwidth_to_bytes(bitwidth)
    is_ipv6 = False
    if (type(x) == list or type(x) == tuple) and len(x) == 1:
        x = x[0]
    if isinstance(x, str):
        logger.info('Converting string value - [%s]', x)
        if matches_mac(x):
            logger.debug('Encoding [%s] as a MAC value', x)
            encoded_bytes = encode_mac(x)
        elif matches_ipv4(x):
            logger.debug('Encoding [%s] as a IPv4 value', x)
            encoded_bytes = encode_ipv4(x)
        elif matches_ipv6(x):
            logger.debug('Encoding [%s] as a IPv6 value', x)
            is_ipv6 = True
            encoded_bytes = encode_ipv6(x)
            logger.debug('Encoded IPv6 - [%s]', encoded_bytes)
        else:
            # Assume that the string is already encoded
            logger.debug('Encoding [%s] as a string value', x)
            encoded_bytes = x
    elif isinstance(x, unicode):
        logger.debug('Encoding [%s] as a unicode value', x)
        t = x.encode('utf-8')
        if matches_mac(t):
            encoded_bytes = encode_mac(t)
        elif matches_ipv4(x):
            encoded_bytes = encode_ipv4(t)
        else:
            # Assume that the string is already encoded
            encoded_bytes = x
    elif type(x) == int:
        logger.debug('Encoding [%s] as a int value', x)
        encoded_bytes = encode_num(x, bitwidth)
    else:
        if x:
            raise SyntaxError(
                "Encoding objects of %r is not supported" % type(x))
        else:
            raise SyntaxError('Value to encode is None')

    logger.debug('Length of encoded bytes - [%s] - bitwidth_bytes - [%s]',
                 len(encoded_bytes), bitwidth_bytes)
    if not is_ipv6:
        assert (len(encoded_bytes) == bitwidth_bytes)
    return encoded_bytes
