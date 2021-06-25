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
    mac = kwargs['mac']
    port = kwargs['port']
    ip_addr = kwargs['ip_addr']
    ipv6_addr = kwargs['ipv6_addr']

    ipv4 = ipaddress.ip_address(ip_addr)
    ipv6 = ipaddress.ip_address(ipv6_addr)
    hash_str = "{}|{}|{}|{}".format(mac, port, ipv4, ipv6)

    logger.info("Creating drop hash value with [%s]", hash_str)
    hash_hex = hashlib.sha256(hash_str.encode()).hexdigest()
    hash_hex_16 = hash_hex[:16]
    hash_int = int(hash_hex_16, 16)
    logger.info("hash int value [%s]", hash_int)
    return hash_int
