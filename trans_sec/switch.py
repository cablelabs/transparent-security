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

import ipaddress
import logging
from queue import Queue
from abc import abstractmethod
from datetime import datetime

import grpc

MSG_LOG_MAX_LEN = 1024

logger = logging.getLogger('switch')


class SwitchConnection(object):

    def __init__(self, sw_info):
        self.sw_info = sw_info
        self.name = sw_info['name']
        self.mac = sw_info['mac']
        self.type = sw_info['type']
        self.device_id = sw_info['id']
        self.int_device_id = sw_info.get('int_id', sw_info['id'])
        self.grpc_addr = sw_info['grpc']

    @abstractmethod
    def start(self, ansible_inventory, controller_user):
        raise NotImplemented

    @abstractmethod
    def stop(self):
        raise NotImplemented

    @staticmethod
    def parse_attack(**kwargs):
        dst_ip = ipaddress.ip_address(kwargs['dst_ip'])
        action_name = 'data_drop'

        logger.info('Attack dst_ip - [%s]', dst_ip)
        # TODO - Add back source IP address as a match field after adding
        #  mitigation at the Aggregate
        dst_ipv4 = 0
        dst_ipv6 = 0
        if dst_ip.version == 6:
            logger.debug('Attack is IPv6')
            dst_ipv6 = str(dst_ip.exploded)
        else:
            logger.debug('Attack is IPv4')
            dst_ipv4 = str(dst_ip.exploded)

        return action_name, dst_ipv4, dst_ipv6

    def add_switch_id(self):
        pass


class GrpcRequestLogger(grpc.UnaryUnaryClientInterceptor,
                        grpc.UnaryStreamClientInterceptor):
    """Implementation of a gRPC interceptor that logs request to a file"""

    def __init__(self, log_file):
        self.log_file = log_file
        with open(self.log_file, 'w') as f:
            # Clear content if it exists.
            f.write("")

    def log_message(self, method_name, body):
        with open(self.log_file, 'a') as f:
            ts = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
            msg = str(body)
            f.write("\n[%s] %s\n---\n" % (ts, method_name))
            if len(msg) < MSG_LOG_MAX_LEN:
                f.write(str(body))
            else:
                f.write(
                    "Message too long (%d bytes)! Skipping log...\n" % len(
                        msg))
            f.write('---\n')

    def intercept_unary_unary(self, continuation, client_call_details,
                              request):
        self.log_message(client_call_details.method, request)
        return continuation(client_call_details, request)

    def intercept_unary_stream(self, continuation, client_call_details,
                               request):
        self.log_message(client_call_details.method, request)
        return continuation(client_call_details, request)


class IterableQueue(Queue):
    _sentinel = object()

    def __iter__(self):
        return iter(self.get, self._sentinel)

    def close(self):
        self.put(self._sentinel)
