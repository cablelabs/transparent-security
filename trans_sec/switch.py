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

import codecs
import ipaddress
import logging
from queue import Queue
from abc import abstractmethod
from datetime import datetime

import grpc
from threading import Thread

from trans_sec.utils.convert import decode_mac

MSG_LOG_MAX_LEN = 1024

logger = logging.getLogger('switch')


class SwitchConnection(object):

    def __init__(self, sw_info):
        self.sw_info = sw_info
        self.name = sw_info['name']
        self.mac = sw_info['mac']
        self.type = sw_info['type']
        self.device_id = sw_info['id']
        self.grpc_addr = sw_info['grpc']
        self.digest_thread = Thread(target=self.receive_digests)

    @abstractmethod
    def start_digest_listeners(self):
        raise NotImplemented

    @abstractmethod
    def stop_digest_listeners(self):
        raise NotImplemented

    def receive_digests(self):
        """
        Runnable method for self.digest_thread
        """
        logger.info("Started listening digest thread on device [%s] with "
                    "name [%s]", self.grpc_addr, self.name)
        while True:
            try:
                logger.debug('Requesting digests from device [%s]',
                             self.grpc_addr)
                digests = self.digest_list()
                logger.debug('digests from device [%s] - [%s]',
                             self.grpc_addr, digests)
                digest_data = digests.digest.data
                logger.debug('Received digest data from device [%s]: [%s]',
                             self.grpc_addr, digest_data)
                self.interpret_digest(digest_data)
                logger.debug('Interpreted digest data')
            except Exception as e:
                logger.error(
                    'Unexpected error reading digest from device [%s] - [%s]',
                    self.grpc_addr, e)

    def interpret_digest(self, digest_data):
        logger.debug("Digest data from switch [%s] - [%s]",
                     self.name, digest_data)

        if not digest_data or len(digest_data) == 0:
            logger.warning('No digest data to process')
            return
        for members in digest_data:
            logger.debug("Digest members: %s", members)
            if members.WhichOneof('data') == 'struct':
                source_mac = decode_mac(members.struct.members[0].bitstring)
                if source_mac:
                    logger.debug('Digest MAC Address is: %s', source_mac)
                    ingress_port = int(
                        codecs.encode(members.struct.members[1].bitstring,
                                      'hex'), 16)
                    logger.debug('Digest Ingress Port is %s', ingress_port)
                    self.add_data_forward(source_mac, ingress_port)
                else:
                    logger.warning('Could not retrieve source_mac from digest')
            else:
                logger.warning('Digest could not be processed - [%s]',
                               digest_data)

        logger.info('Completed digest processing')

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

    @abstractmethod
    def get_table_entry(self, table_name, action_name, match_fields,
                        action_params, ingress_class=True):
        raise NotImplemented

    @abstractmethod
    def add_data_forward(self, dst_mac, egress_port):
        raise NotImplemented

    @abstractmethod
    def del_data_forward(self, dst_mac):
        raise NotImplemented

    @abstractmethod
    def add_data_inspection(self, **kwargs):
        raise NotImplemented

    @abstractmethod
    def del_data_inspection(self, **kwargs):
        raise NotImplemented

    def add_attack(self, **kwargs):
        logger.info('Switch does not support attack mitigation')
        pass

    def stop_attack(self, **kwargs):
        logger.info('Switch does not support attack mitigation')
        pass

    def add_switch_id(self, dev_id):
        pass

    @abstractmethod
    def build_device_config(self):
        raise NotImplemented

    @abstractmethod
    def master_arbitration_update(self):
        raise NotImplemented

    @abstractmethod
    def set_forwarding_pipeline_config(self, device_config):
        raise NotImplemented

    @abstractmethod
    def write_table_entry(self, **kwargs):
        raise NotImplemented

    @abstractmethod
    def delete_table_entry(self, **kwargs):
        raise NotImplemented

    @abstractmethod
    def get_data_forward_macs(self):
        """
        Returns the key MAC values from the data_forward_t table
        :return: set dst_mac values
        """
        raise NotImplemented

    @abstractmethod
    def get_data_inspection_src_mac_keys(self):
        """
        Returns a set of macs that is a key to the data_inspection_t table
        :return: set src_mac values
        """
        raise NotImplemented

    @abstractmethod
    def get_match_values(self, table_name):
        """
        Returns a dict of match values in a list of dict where the dict
        objects' keys will be the field name and the value will be the raw
        byte value to be converted by the client
        :param table_name: the name of the table to query
        :return: a list of dict
        """
        raise NotImplemented

    @abstractmethod
    def get_table_entries(self, table_name):
        """
        Returns a P4Runtime object for iterating through a table
        :param table_name:
        :return:
        """
        raise NotImplemented

    @abstractmethod
    def read_table_entries(self, table_id=None):
        raise NotImplemented

    @abstractmethod
    def write_clone_entries(self, pre_entry):
        raise NotImplemented

    @abstractmethod
    def delete_clone_entries(self, pre_entry):
        raise NotImplemented

    @abstractmethod
    def read_counters(self, counter_id=None, index=None):
        raise NotImplemented

    @abstractmethod
    def reset_counters(self, counter_id=None, index=None):
        raise NotImplemented

    @abstractmethod
    def write_digest_entry(self, digest_entry):
        raise NotImplemented

    @abstractmethod
    def digest_list_ack(self, digest_ack):
        raise NotImplemented

    @abstractmethod
    def digest_list(self):
        raise NotImplemented

    @abstractmethod
    def write_multicast_entry(self, hosts):
        raise NotImplemented

    @abstractmethod
    def write_arp_flood(self):
        raise NotImplemented


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
