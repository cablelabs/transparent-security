# Copyright (c) 2020 Cable Television Laboratories, Inc.
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
import hashlib
import ipaddress
import logging

logger = logging.getLogger('tps_utils')


def create_attack_hash(**kwargs):
    logger.info('Attack dict to hash - [%s]', kwargs)

    mac = kwargs.get('mac')
    if not mac:
        mac = kwargs['src_mac']

    port = kwargs.get('port')
    if not port:
        port = kwargs['dst_port']

    ip_addr = kwargs.get('ip_addr')
    ipv6_addr = kwargs.get('ipv6_addr')

    if not ip_addr or not ipv6_addr:
        ip_ver = kwargs['ip_ver']
        if ip_ver == 4:
            ip_addr = kwargs['dst_ip']
            ipv6_addr = '::'
        else:
            ipv6_addr = kwargs['dst_ip']
            ip_addr = '0.0.0.0'

    ipv4 = ipaddress.ip_address(ip_addr)
    ipv6 = ipaddress.ip_address(ipv6_addr)
    hash_str = "{}|{}|{}|{}".format(mac, port, ipv4, ipv6)

    logger.debug("Creating drop hash value with [%s]", hash_str)
    hash_hex = hashlib.sha256(hash_str.encode()).hexdigest()
    hash_hex_16 = hash_hex[:16]
    logger.debug("hash_hex_16 - [%s]", hash_hex_16)
    hash_int = int(hash_hex_16, 16)
    logger.debug("hash int value [%s]", hash_int)
    return hash_int
