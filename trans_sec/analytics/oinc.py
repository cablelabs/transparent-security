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
import abc
import datetime
import logging
import time

from anytree import search, Node, RenderTree
from scapy.all import bind_layers
from scapy.all import sniff
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
import threading
from trans_sec.packet.inspect_layer import GatewayINTInspect

logger = logging.getLogger('oinc')


class PacketAnalytics(object):
    """
    Analytics Engine class
    """
    def __init__(self, sdn_interface, packet_count=100, sample_interval=60):
        """
        Constructor
        :param sdn_interface: the HTTP interface to the SDN Controller
        :param packet_count: the number of packets to trigger an attack
        :param sample_interval: the interval in seconds used for counting the
                                packets
        """
        self.sdn_interface = sdn_interface
        self.packet_count = packet_count
        self.sample_interval = sample_interval
        self.count_map = dict()
        self.sniff_stop = threading.Event()

    def start_sniffing(self, iface, proto_id, ether_type):
        """
        Starts the sniffer thread
        :param iface: the interface to sniff
        :param proto_id:
        :param ether_type: the type of packets to process
                           (i.e. 0x1212 for Ethernet)
        """
        logger.info("AE monitoring iface %s", iface)
        bind_layers(Ether, GatewayINTInspect, type=ether_type)
        bind_layers(GatewayINTInspect, IP, proto_id=proto_id)
        sniff(iface=iface,
              prn=lambda packet: self.handle_packet(packet, ether_type),
              stop_filter=lambda p: self.sniff_stop.is_set())

    def stop_sniffing(self):
        """
        Stops the sniffer thread
        """
        self.sniff_stop.set()

    def handle_packet(self, packet, ether_type=None):
        """
        Determines whether or not to process this packet
        :param packet: the packet to process
        :param ether_type: the type of packet to process
        :return T/F - True when an attack has been triggered
        """
        if not ether_type or (ether_type and packet[Ether].type == ether_type):
            return self.process_packet(packet)
        else:
            logger.debug('Could not process packet with ether type %s',
                         ether_type)
            return False

    def _send_attack(self, **attack_dict):
        """
        Sends an HTTP POST to the SDN controllers HTTP interface 'attack'
        :param attack_dict: the data to send
        :raises Exception: due to the remote HTTP POST
        """
        logger.info('Start attack - %s', attack_dict)
        self.sdn_interface.post('attack', attack_dict)

    @abc.abstractmethod
    def process_packet(self, packet):
        """
        Processes a packet to determine if an attack is occurring
        :param packet: the packet to process
        :return: T/F - True when an attack has been triggered
        """
        return


def extract_int_data(packet):
    """
    Parses the required data from the packet
    :param packet: the packet to parse
    :return:
    """
    out = dict(
        devMac=packet[GatewayINTInspect].srcAddr,
        devAddr=packet[GatewayINTInspect].deviceAddr,
        dstAddr=packet[IP].dst,
        dstPort=packet[UDP].dport,
        protocol=packet[GatewayINTInspect].proto_id,
        packetLen=len(packet),
    )
    logger.debug('Extracted header data [%s]', out)
    return out


class Oinc(PacketAnalytics):
    """
    Oinc implementation of PacketAnalytics
    """
    def __init__(self, sdn_interface, packet_count=100, sample_interval=60):
        super(self.__class__, self).__init__(sdn_interface, packet_count,
                                             sample_interval)
        self.tree = Node('root')

    def process_packet(self, packet):
        mac, src_ip, dst_ip, dst_port, packet_size = self.__parse_tree(packet)

        if mac:
            if src_ip and dst_ip and dst_port and packet_size:
                self.__packet_with_mac(mac, src_ip, dst_ip, dst_port,
                                       packet_size)
        self.__manage_tree()

    def __parse_tree(self, packet):
        """
        Processes a packet from a new device that has not been counted
        """
        info = extract_int_data(packet)
        logger.info('Processing packet with info [%s]', info)

        macs = search.findall_by_attr(self.tree, info.get('srcMac'),
                                      name='name', maxlevel=2, maxcount=1)

        mac = None
        src_ip = None
        dst_ip = None
        dst_port = None
        packet_size = None

        if len(macs) > 0:
            mac = macs[0]
            src_ips = search.findall_by_attr(
                mac, info.get('srcIP'), name='name', maxlevel=2, maxcount=1)
            if len(src_ips) is not 0:
                src_ip = src_ips[0]
                dst_ips = search.findall_by_attr(
                    src_ip, info.get('dstIP'), name='name', maxlevel=2,
                    maxcount=1)
                if len(dst_ips) is not 0:
                    dst_ip = dst_ips[0]
                    logger.info('Processing source IPs - %s', src_ips)
                    dst_ports = search.findall_by_attr(
                        dst_ip, info.get('dstPort'), name='name',
                        maxlevel=2, maxcount=1)
                    if len(dst_ports) is not 0:
                        dst_port = dst_ports[0]
                        packet_sizes = search.findall_by_attr(
                            dst_port, info.get('packet_size'),
                            name='name', maxlevel=2, maxcount=1)
                        if len(packet_sizes) is not 0:
                            packet_size = packet_sizes[0]

        return mac, src_ip, dst_ip, dst_port, packet_size

    def __manage_tree(self):
        """
        Updates the tree
        I don't think this routine does anything at all
        """
        for pre, fill, node in RenderTree(self.tree):
            if node.name is 'count':
                logger.info(
                    "Tree info %s%s: %s %s p/s attack: %s",
                    pre, node.name, node.value, node.pps, node.attack)
            else:
                logger.info("Pre - [%s], Fill - [%s], Node - [%s]",
                            pre, fill, node.name)

    def __packet_with_mac(self, mac, src_ip, dst_ip, dst_port, packet_size):
        """
        Processes a packet from an existing device that has been counted
        """
        logger.info('Packet with MAC [%s] and source IP [%s]', mac, src_ip)
        count = packet_size.children[0]
        count.value = count.value + 1
        base_time = count.time
        current_time = datetime.datetime.today()
        delta = (current_time - base_time).total_seconds()
        count.pps = count.value / delta
        if (count.value > 3 and count.pps > 100
                and not count.attack):
            logger.info('UDP Flood attack detected')
            count.attack = True

            # Send to SDN
            try:
                self._send_attack(**dict(
                    src_mac=mac.name,
                    src_ip=src_ip.name,
                    dst_ip=dst_ip.name,
                    dst_port=dst_port.name,
                    packet_size=packet_size.name,
                    attack_type='UDP Flood'))
            except Exception as e:
                logger.error('Unexpected error [%s]', e)

        if delta > 60:
            count.time = current_time
            count.value = 1


class SimpleAE(PacketAnalytics):
    """
    Simple implementation of PacketAnalytics where the count for detecting
    attack notifications is based on the unique hash of the extracted INT data
    """
    def __init__(self, sdn_interface, packet_count=100, sample_interval=60):
        super(self.__class__, self).__init__(sdn_interface, packet_count,
                                             sample_interval)
        # Holds the last time an attack call was issued to the SDN controller
        self.attack_map = dict()

    def process_packet(self, packet):
        """
        Processes a packet to determine if an attack is occurring
        :param packet: the packet to process
        :return: T/F - True when an attack has been triggered
        """
        logger.debug('Packet data - [%s]', packet.summary())
        int_data = extract_int_data(packet)
        attack_map_key = hash(str(int_data))
        if not self.count_map.get(attack_map_key):
            self.count_map[attack_map_key] = list()

        curr_time = datetime.datetime.now()
        self.count_map.get(attack_map_key).append(curr_time)
        times = self.count_map.get(attack_map_key)
        count = 0
        for eval_time in times:
            delta = (curr_time - eval_time).total_seconds()
            if delta > self.sample_interval:
                times.remove(eval_time)
            else:
                count += 1

        if count > self.packet_count:
            logger.debug('Attack detected - count [%s] with key [%s]',
                         count, attack_map_key)

            attack_dict = dict(
                src_mac=int_data['devMac'],
                src_ip=int_data['devAddr'],
                dst_ip=int_data['dstAddr'],
                dst_port=int_data['dstPort'],
                packet_size=int_data['packetLen'],
                attack_type='UDP Flood')

            # Send to SDN
            last_attack = self.attack_map.get(attack_map_key)
            if not last_attack or time.time() - last_attack > 1:
                logger.info('Calling SDN, last attack sent - [%s]',
                            last_attack)
                try:
                    self.attack_map[attack_map_key] = time.time()
                    self._send_attack(**attack_dict)
                    return True
                except Exception as e:
                    logger.error('Unexpected error [%s]', e)
                    return False
            else:
                logger.debug(
                    'Not calling SDN as last attack notification for %s'
                    ' was only %s seconds ago',
                    attack_dict, time.time() - last_attack)
                return False
        else:
            logger.debug('No attack detected - count [%s]', count)
            return False


class IntLoggerAE(PacketAnalytics):
    """
    Logs only INT packets
    """
    def process_packet(self, packet):
        """
        Logs the INT data within the packet
        :param packet: the INT packet
        :return: False
        """
        logger.info('INT Packet data - [%s]', extract_int_data(packet))
        return False


class LoggerAE(PacketAnalytics):
    """
    Logging only
    """
    def handle_packet(self, packet, ether_type=None):
        """
        Logs every received packet's summary data
        :param packet: extracts data from here
        :param ether_type: does nothing here
        :return: False
        """
        logger.info('Packet data - [%s]', packet.summary())
        return False

    def process_packet(self, packet):
        """
        No need to implement
        :param packet: the packet that'll never come in
        :raises NotImplemented
        """
        raise NotImplemented
