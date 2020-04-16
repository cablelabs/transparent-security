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
from logging import getLogger
from threading import Thread
from trans_sec.controller.abstract_controller import AbstractController
from trans_sec.utils.convert import decode_mac, decode_ipv4

logger = getLogger('aggregate_controller')


class AggregateController(AbstractController):
    """
    Implementation of the controller for a switch running the aggregate.p4
    program
    """
    def __init__(self, platform, p4_build_out, topo, log_dir, load_p4=True):
        super(self.__class__, self).__init__(
            platform, p4_build_out, topo, 'aggregate',
            ['TpsAggIngress.forwardedPackets'],
            log_dir, load_p4, 'TpsAggIngress')
        self.known_devices = set()

    def make_north_rules(self, sw, sw_info, north_link):
        if north_link.get('north_facing_port'):
            logger.info('Creating north switch rules - [%s]', north_link)
            north_node = self.topo['switches'][north_link['north_node']]
            logger.info(
                'Aggregate: %s connects northbound to Core: %s on physical '
                'port %s to physical port %s',
                sw_info['name'], north_node,
                north_link.get('north_facing_port'),
                north_link.get('south_facing_port'))

            inet = self.topo['hosts']['inet']

            # Add IPv6 entry
            table_entry = self.p4info_helper.build_table_entry(
                table_name='{}.data_forward_ipv6_t'.format(self.p4_ingress),
                match_fields={
                    'hdr.ipv6.dstAddr': (inet['ipv6'], 128)
                },
                action_name='{}.data_forward'.format(self.p4_ingress),
                action_params={
                    'dstAddr': north_node['mac'],
                    'port': north_link['north_facing_port']
                })
            sw.write_table_entry(table_entry)

            logger.info('Installed Northbound from port %s to port %s',
                        north_link.get('north_facing_port'),
                        north_link.get('south_facing_port'))
        else:
            logger.info('No north links to install')

    def add_data_inspection(self, sw, device, sw_info):
        action_params = {
            'device': device['id'],
            'switch_id': sw_info['id']
        }
        table_entry = self.p4info_helper.build_table_entry(
            table_name='{}.data_inspection_t'.format(self.p4_ingress),
            match_fields={'hdr.ethernet.src_mac': device['mac']},
            action_name='{}.data_inspect_packet'.format(
                self.p4_ingress),
            action_params=action_params)
        sw.write_table_entry(table_entry)
        logger.info(
            'Installed Northbound Packet Inspection for device - [%s]'
            ' with MAC - [%s] with action params - [%s]',
            self.switch_type, device.get('mac'), action_params)

    def set_multicast_group(self, sw, sw_info):
        mc_group_id = 1
        replicas = [
                    {'egress_port': '1', 'instance': '1'},
                    {'egress_port': '2', 'instance': '1'},
                    {'egress_port': '3', 'instance': '1'},
                    {'egress_port': '4', 'instance': '1'}
                    ]

        multicast_entry = self.p4info_helper.build_multicast_group_entry(mc_group_id, replicas)
        logger.info('Build Multicast Entry: %s', multicast_entry)
        sw.write_multicast_entry(multicast_entry)
        table_entry = self.p4info_helper.build_table_entry(
            table_name='{}.mac_learn_t'.format(self.p4_ingress),
            match_fields={'hdr.ethernet.dst_mac': 'ff:ff:ff:ff:ff:ff'},
            action_name='{}.arp_flood'.format(self.p4_ingress),
            action_params={
                'srcAddr': sw_info['mac']
            })
        sw.write_table_entry(table_entry)

    def add_data_forward(self, sw, sw_info, src_ip, mac, port):
        logger.info("Aggregate - Check if %s belongs to: %s", src_ip, list(self.known_devices))
        if src_ip not in list(self.known_devices):
            logger.info("Adding unique table entry on %s for %s", sw_info['name'], src_ip)
            table_entry = self.p4info_helper.build_table_entry(
                table_name='{}.data_forward_ipv4_t'.format(self.p4_ingress),
                match_fields={
                    'hdr.ipv4.dstAddr': (src_ip, 32)
                },
                action_name='{}.data_forward'.format(self.p4_ingress),
                action_params={
                    'dstAddr': mac,
                    'port': port
                })
            sw.write_table_entry(table_entry)
            table_entry = self.p4info_helper.build_table_entry(
                table_name='{}.arp_reply_t'.format(self.p4_ingress),
                match_fields={'hdr.arp.dstAddr': (src_ip, 32)},
                action_name='{}.arp_reply'.format(self.p4_ingress),
                action_params={
                    'srcAddr': sw_info['mac'],
                    'dstAddr': mac,
                    'port': port
                })
            sw.write_table_entry(table_entry)
        self.known_devices.add(src_ip)

    def interpret_digest(self, sw, sw_info, digest_data):
        for members in digest_data:
            if members.WhichOneof('data') == 'struct':
                source_ip = decode_ipv4(members.struct.members[0].bitstring)
                logger.info('Learned IP Address is: %s', source_ip)
                source_mac = decode_mac(members.struct.members[1].bitstring)
                logger.info('Learned MAC Address is: %s', source_mac)
                ingress_port = int(members.struct.members[2].bitstring.encode('hex'), 16)
                logger.info('Ingress Port is %s', ingress_port)
                self.add_data_forward(sw, sw_info, source_ip, source_mac, ingress_port)

    def receive_digests(self, sw, sw_info):
        logger.info("Started listening thread for %s", sw_info['name'])
        while True:
            digests = sw.digest_list()
            digest_data = digests.digest.data
            logger.info('Received digests: [%s]', digests)
            self.interpret_digest(sw, sw_info, digest_data)

    def send_digest_entry(self, sw, sw_info):
        digest_entry = self.p4info_helper.build_digest_entry(digest_name="mac_learn_digest")
        sw.write_digest_entry(digest_entry)
        logger.info('Aggregate: Sent Digest Entry via P4Runtime: [%s]', digest_entry)
        digest_list = Thread(target=self.receive_digests, args=(sw, sw_info))
        digest_list.start()
