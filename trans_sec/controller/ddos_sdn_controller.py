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
import ast
import socket
from logging import getLogger

import ipaddress
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.sendrecv import sendp

from trans_sec.packet.inspect_layer import UdpInt, DropReport
from time import sleep
import threading
import time

from trans_sec.consts import (DRPT_LEN, UDP_HDR_LEN, UDP_INT_HDR_LEN,
                              IPV4_HDR_LEN, DRPT_PAYLOAD_LEN)
from trans_sec import consts
from trans_sec.controller.http_server_flask import SDNControllerServer

# Logger stuff
from trans_sec.utils import tps_utils

logger = getLogger('ddos_sdn_controller')

AGG_CTRL_KEY = 'aggregate'
CORE_CTRL_KEY = 'core'


class DdosSdnController:
    """
    SDN controller for quelling DDoS attacks
    """
    def __init__(self, topo, controllers, http_server_port, controller_user,
                 ansible_inventory, ae_ip_str=None, drop_rpt_freq=10,
                 is_delta=False):

        self.topo = topo
        self.controllers = controllers
        self.http_server = SDNControllerServer(self, http_server_port)
        self.drop_rpt_thread = threading.Thread(target=self.create_drop_report)
        self.ansible_inventory = ansible_inventory
        self.controller_user = controller_user
        self.running = False
        self.is_delta = is_delta
        if ae_ip_str:
            self.ae_ip = ipaddress.ip_address(ae_ip_str)
        else:
            self.ae_ip = None
        self.drop_rpt_freq = drop_rpt_freq
        self.drop_rpt_count = dict()

    def start(self):
        logger.info('Starting Controllers - [%s]', self.controllers)
        for controller in self.controllers.values():
            controller.start(self.ansible_inventory, self.controller_user)

        logger.info('Starting HTTP server on port - [%s]',
                    self.http_server.port)
        self.http_server.start()
        logger.info('Starting drop report thread')
        self.drop_rpt_thread.start()
        logger.info('Starting main loop')
        self.__main_loop()

    def stop(self):
        logger.info('Stopping SDN controller')
        self.running = False
        self.http_server.stop()
        self.drop_rpt_thread.join()

    def create_drop_report(self):
        while True:
            self.send_drop_report()
            sleep(self.drop_rpt_freq)

    def send_drop_report(self):
        logger.info('Attempting to send drop report')
        if self.ae_ip:
            self.__create_drop_report()
        else:
            logger.debug('No configured AE IP to send drop report')

    def __create_drop_report(self):
        for controller in self.controllers.values():
            if controller == self.get_agg_controller():
                logger.info("Creating drop report for controller: %s",
                            controller)
                drp_entries = controller.count_dropped_packets()
                for match_keys, drop_count in drp_entries:
                    if match_keys != 0:
                        logger.debug('Match keys - [%s]', match_keys)
                        attack_key = tps_utils.create_attack_hash(**match_keys)
                        logger.debug(
                            'Attack key value - [%s] and drop report delta '
                            'mode - [%s]', attack_key, self.is_delta)
                        if attack_key:
                            if self.is_delta:
                                old_count = self.drop_rpt_count.get(attack_key)
                                logger.debug('Previous drop count - [%s]',
                                             old_count)
                                if not old_count:
                                    old_count = 0
                                rpt_count = drop_count - old_count
                                self.drop_rpt_count[attack_key] = drop_count
                            else:
                                rpt_count = drop_count
                            self.__send_drop_pkt(attack_key, rpt_count)
                    else:
                        logger.debug('No drops to report')

    def __send_drop_pkt(self, attack_key, rpt_count):
        host_name = socket.gethostname()

        sdn_ip = socket.gethostbyname(host_name)
        ip_len = (IPV4_HDR_LEN + UDP_INT_HDR_LEN + DRPT_LEN
                  + UDP_HDR_LEN + DRPT_PAYLOAD_LEN)
        udp_int_len = ip_len - IPV4_HDR_LEN
        udp_len = UDP_HDR_LEN + DRPT_PAYLOAD_LEN
        drop_pkt = Ether(type=consts.IPV4_TYPE)
        drop_pkt = drop_pkt / IP(
            dst=str(self.ae_ip), src=sdn_ip, len=ip_len,
            proto=consts.UDP_PROTO)
        drop_pkt = drop_pkt / UdpInt(sport=consts.UDP_INT_SRC_PORT,
                                     dport=consts.UDP_TRPT_DST_PORT,
                                     len=udp_int_len)
        drop_pkt = drop_pkt / DropReport(
            ver=consts.DRPT_VER,
            node_id=self.topo['switches']['aggregate']['int_id'],
            in_type=consts.DRPT_IN_TYPE,
            rpt_len=consts.DRPT_REP_LEN, md_len=consts.DRPT_MD_LEN,
            rep_md_bits=consts.DRPT_MD_BITS,
            domain_id=consts.TRPT_DOMAIN_ID,
            var_opt_bsmd=consts.DRPT_BS_MD,
            timestamp=int(time.time()),
            drop_count=rpt_count,
            drop_hash=attack_key)
        drop_pkt = drop_pkt / UDP(dport=consts.UDP_DRPT_DST_PORT,
                                  sport=consts.UDP_DRPT_SRC_PORT,
                                  len=udp_len)
        drop_pkt = drop_pkt / 'tps drop report'
        try:
            sendp(drop_pkt, verbose=2)
            logger.info(
                "Sent Drop Report with attack key - [%s], and count - [%s]",
                attack_key, rpt_count)
        except Exception as e:
            logger.info("Unable to send drop report - [%s]", e)

    def add_data_forward(self, df_req):
        """
        Adds a data forward table entry into the expected switch
        """
        self.__data_forward(df_req)

    def del_data_forward(self, df_req):
        """
        Adds a data forward table entry into the expected switch
        """
        self.__data_forward(df_req, True)

    def __data_forward(self, df_req, del_flag=False):
        """
        Removes a device to mitigate an attack
        """
        logger.debug('df_req - [%s]', df_req)
        for key, controller in self.controllers.items():
            for switch in controller.switches:
                logger.debug('switch - [%s]', switch.device_id)
                if switch.mac == df_req['switch_mac']:
                    if del_flag:
                        switch.del_data_forward(df_req['dst_mac'])
                    else:
                        try:
                            switch.add_data_forward(df_req['dst_mac'],
                                                    df_req['output_port'])
                        except Exception as e:
                            if 'ALREADY_EXISTS' in str(e):
                                pass
                            else:
                                raise e
                    return

        logger.warning('Could not find switch with switch_mac - [%s]',
                       df_req['switch_mac'])

    def add_data_inspection(self, di_req):
        """
        Adds a data inspection table entry into the expected switch
        """
        self.__data_inspection(di_req)

    def del_data_inspection(self, di_req):
        """
        Adds a data inspection table entry into the expected switch
        """
        self.__data_inspection(di_req, True)

    def __data_inspection(self, di_req, del_flag=False):
        """
        Removes a device to mitigate an attack
        """
        logger.debug('di_req - [%s]', di_req)
        for key, controller in self.controllers.items():
            for switch in controller.switches:
                logger.debug('switch - [%s]', switch.device_id)
                if switch.mac == di_req['switch_mac']:
                    if del_flag:
                        switch.del_data_inspection(
                            di_req['device_id'], di_req['device_mac'])
                    else:
                        switch.add_data_inspection(
                            di_req['device_id'], di_req['device_mac'])
                    return

        logger.warning('Could not find switch with device_id - [%s]',
                       di_req['device_id'])

    def remove_agg_attacker(self, attack):
        """
        Removes a device to mitigate an attack
        :param attack: dict of attack
        """
        agg_controller = self.get_agg_controller()
        logger.info(
            'Removing attack from aggregate with attack - [%s]', attack)
        if agg_controller:
            try:
                agg_controller.remove_agg_attacker(attack)
            except Exception as e:
                logger.error('Error removing attacker with error - [%s])', e)
        else:
            logger.warning('Aggregate controller cannot stop the attack')

    def add_agg_attacker(self, attack):
        """
        Adds a device to mitigate an attack
        :param attack: dict of attack
        """
        agg_controller = self.get_agg_controller()
        logger.info('Adding attack to aggregate')
        if agg_controller:
            try:
                agg_controller.add_attacker(attack, None)
            except Exception as e:
                logger.error(
                    'Error adding aggregate attacker with error - [%s])', e)
        else:
            logger.warning('Aggregate controller cannot add attack')

    def activate_telem_rpt(self, request):
        """
        Adds a device to mitigate an attack
        :param request: dict of the request
        """
        core_controller = self.get_core_controller()
        logger.info('Activating telemetry report for core')
        if core_controller:
            try:
                core_controller.setup_telem_rpt(**request)
            except Exception as e:
                logger.error(
                    'Error setting up telemetry report with error - [%s])', e)
        else:
            logger.warning('Aggregate controller cannot add attack')

    def update_dflt_port(self, request):
        """
        Updates the default port
        :param request: dict of the request
        """
        logger.debug('request - [%s]', request)
        for key, controller in self.controllers.items():
            for switch in controller.switches:
                logger.debug('switch - [%s]', switch.device_id)
                if switch.mac == request['switch_mac']:
                    switch.update_default_port(request['port'])

    def update_mcast_grp(self, request):
        """
        Updates the mcast ports
        :param request: dict of the request
        """
        logger.debug('Update mcast request - [%s]', request)
        for key, controller in self.controllers.items():
            for switch in controller.switches:
                logger.debug('switch mac - [%s], request mac - [%s]',
                             switch.mac, request['switch_mac'])
                if switch.mac == request['switch_mac']:
                    logger.debug('Update mcast on - [%s]', switch.mac)
                    ports = ast.literal_eval(request['ports'])
                    logger.debug('Ports to update - [%s]', ports)
                    switch.update_arp_multicast(ports=ports)

    def get_mcast_grp_ports(self, request):
        """
        Retrieve the mcast ports
        :param request: dict of the request
        """
        logger.debug('Retrieve mcast ports - [%s]', request)
        for key, controller in self.controllers.items():
            for switch in controller.switches:
                logger.debug('switch - [%s]', switch.device_id)
                if switch.mac == request['switch_mac']:
                    return switch.get_arp_multicast_ports()

    def set_trpt_sampling_value(self, request):
        """
        Adds a device to mitigate an attack
        :param request: dict of the request
        """
        core_controller = self.get_core_controller()
        logger.info('Setting telemetry report sampling value to core')
        sample_size = request.get('sample')
        if core_controller and sample_size:
            try:
                logger.info('Adding sample_size - [%s]', sample_size)
                core_controller.set_trpt_sampling_value(int(sample_size))
            except Exception as e:
                logger.error(
                    'Error setting TRPT sample value with error - [%s])', e)
        else:
            logger.warning('Aggregate controller cannot add attack')

    def deactivate_telem_rpt(self, request):
        """
        Adds a device to mitigate an attack
        :param request: dict of the request
        """
        core_controller = self.get_core_controller()
        logger.info('Deactivating telemetry report config to core')
        if core_controller:
            try:
                core_controller.setup_telem_rpt(**request)
            except Exception as e:
                logger.error('Error adding attacker with error - [%s])', e)
        else:
            logger.warning('Aggregate controller cannot add attack')

    def get_agg_controller(self):
        agg_controller = self.controllers.get(AGG_CTRL_KEY)
        return agg_controller

    def get_core_controller(self):
        core_controller = self.controllers.get(CORE_CTRL_KEY)
        return core_controller

    def __main_loop(self):
        """
        Starts polling thread/Error adding attacker to host
        """
        logger.info('Starting thread')
        self.running = True
        try:
            while self.running:
                logger.info('SDN Controller heartbeat')
                sleep(10)
        except KeyboardInterrupt:
            logger.warning(' Shutting down.')
