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
    return mac_addr_string.replace(':', '').decode('hex')


def decode_mac(encoded_mac_addr):
    return ':'.join(s.encode('hex') for s in encoded_mac_addr)


ip_pattern = re.compile(r'^(\d{1,3}\.){3}(\d{1,3})$')


def matches_ipv4(ip_addr_string):
    return ip_pattern.match(ip_addr_string) is not None


def encode_ipv4(ip_addr_string):
    return socket.inet_aton(ip_addr_string)


def decode_ipv4(encoded_ip_addr):
    return socket.inet_ntoa(encoded_ip_addr)


def bitwidth_to_bytes(bitwidth):
    return int(math.ceil(bitwidth / 8.0))


def encode_num(number, bitwidth):
    bitwidth_bytes = bitwidth_to_bytes(bitwidth)
    num_str = '%x' % number
    if number >= 2 ** bitwidth:
        raise Exception(
            "Number, %d, does not fit in %d bits" % (number, bitwidth))
    return ('0' * (bitwidth_bytes * 2 - len(num_str)) + num_str).decode('hex')


def decode_num(encoded_number):
    return int(encoded_number.encode('hex'), 16)


def encode(x, bitwidth):
    """
    Tries to infer the type of `x` and encode it
    """
    logger.info('Encoding - [%s] with - [%s]', x, bitwidth)
    bitwidth_bytes = bitwidth_to_bytes(bitwidth)
    if (type(x) == list or type(x) == tuple) and len(x) == 1:
        x = x[0]
    if isinstance(x, str):
        logger.debug('Encoding [%s] as a string value', x)
        if matches_mac(x):
            encoded_bytes = encode_mac(x)
        elif matches_ipv4(x):
            encoded_bytes = encode_ipv4(x)
        else:
            # Assume that the string is already encoded
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
            raise Exception(
                "Encoding objects of %r is not supported" % type(x))
        else:
            raise Exception('Value to encode is None')

    logger.debug('Length of encoded bytes - [%s] - bitwidth_bytes - [%s]',
                 len(encoded_bytes), bitwidth_bytes)
    assert (len(encoded_bytes) == bitwidth_bytes)
    return encoded_bytes
