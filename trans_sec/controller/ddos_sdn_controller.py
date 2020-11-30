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
import socket
from logging import getLogger

import hashlib

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
logger = getLogger('ddos_sdn_controller')

AGG_CTRL_KEY = 'aggregate'
CORE_CTRL_KEY = 'core'
GATEWAY_CTRL_KEY = 'gateway'


class DdosSdnController:
    """
    SDN controller for quelling DDoS attacks
    """
    def __init__(self, topo, controllers, http_server_port, ansible_inventory,
                 controller_user):

        self.topo = topo
        self.controllers = controllers
        self.http_server = SDNControllerServer(self, http_server_port)
        self.drop_rpt_thread = threading.Thread(target=self.create_drop_report)
        self.ansible_inventory = ansible_inventory
        self.controller_user = controller_user
        self.running = False

    def start(self):
        logger.info('Starting Controllers - [%s]', self.controllers)
        for controller in self.controllers.values():
            controller.start(self.ansible_inventory, self.controller_user)

        logger.info('Starting HTTP server on port - [%s]',
                    self.http_server.port)
        self.http_server.start()
        self.drop_rpt_thread.start()
        self.__main_loop()

    def stop(self):
        logger.info('Stopping SDN controller')
        self.running = False
        self.http_server.stop()
        self.drop_rpt_thread.join()

    def create_drop_report(self):
        while True:
            self.send_drop_report()
            sleep(10)

    def send_drop_report(self):
        ae_ip = None
        if self.get_core_controller():
            ae_ip_str = self.get_core_controller().get_ae_ip()
            if ae_ip_str:
                try:
                    ae_ip = ipaddress.ip_address(ae_ip_str)
                    logger.info('AE IP Address - [%s]', ae_ip)
                except ValueError as e:
                    logger.warning(
                        'Cannot create drop report, ae_ip invalid - [%s]', e)
                    return
        if ae_ip:
            self.__create_drop_report(ae_ip)

    def __create_drop_report(self, ae_ip):
        for controller in self.controllers.values():
            if controller == self.get_agg_controller():
                logger.info("Creating drop report for controller: %s",
                            controller)
                match_keys, drop_count = controller.count_dropped_packets()
                logger.info("Match keys - [%s]", match_keys)
                logger.info('Dropped packet count - [%s]', drop_count)
                if match_keys and drop_count:
                    key_list = []
                    for key, value in match_keys.items():
                        key_list.append(value['value'])
                    logger.info("Match key list - %s", key_list)
                    keys = int(hashlib.md5(str(key_list).encode()).hexdigest(),
                               16)
                else:
                    keys = 0
                    drop_count = 0
                host_name = socket.gethostname()
                sdn_ip = socket.gethostbyname(host_name)
                ip_len = (IPV4_HDR_LEN + UDP_INT_HDR_LEN + DRPT_LEN
                          + UDP_HDR_LEN + DRPT_PAYLOAD_LEN)
                udp_int_len = ip_len - IPV4_HDR_LEN
                udp_len = UDP_HDR_LEN + DRPT_PAYLOAD_LEN
                drop_pkt = Ether(type=consts.IPV4_TYPE)
                drop_pkt = drop_pkt / IP(
                    dst=str(ae_ip), src=sdn_ip, len=ip_len,
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
                    drop_count=drop_count,
                    drop_tbl_keys=keys)
                drop_pkt = drop_pkt / UDP(dport=consts.UDP_DRPT_DST_PORT,
                                          sport=consts.UDP_DRPT_SRC_PORT,
                                          len=udp_len)
                drop_pkt = drop_pkt / 'tps drop report'
                try:
                    sendp(drop_pkt, verbose=2)
                    logger.info("Sent Drop Report packet")
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

    def remove_attacker(self, attack):
        """
        Removes a device to mitigate an attack
        :param attack: dict of attack
        """
        host, gw_controller = self.__get_attack_host(attack)
        logger.info('Adding attack to gateways with host - [%s]', host)
        try:
            gw_controller.remove_attacker(attack, host)
        except Exception as e:
            logger.error(
                'Error removing attacker to host - [%s] with error - [%s])',
                host, e)

    def add_attacker(self, attack):
        """
        Adds a device to mitigate an attack
        :param attack: dict of attack
        """
        host, gw_controller = self.__get_attack_host(attack)
        logger.info('Adding attack to gateways with host - [%s]', host)
        try:
            gw_controller.add_attacker(attack, host)
        except Exception as e:
            logger.error(
                'Error adding attacker to host - [%s] with error - [%s])',
                host, e)
            raise e

    def remove_agg_attacker(self, attack):
        """
        Removes a device to mitigate an attack
        :param attack: dict of attack
        """
        agg_controller = self.get_agg_controller()
        logger.info('Removing attack from aggregate')
        if agg_controller:
            try:
                agg_controller.remove_attacker(attack, None)
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
                logger.error('Error adding attacker with error - [%s])', e)
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

    def __get_attack_host(self, attack):
        """
        Returns the host value or None
        :param attack:
        :return:
        """
        gateway_controller = self.controllers.get(GATEWAY_CTRL_KEY)
        if gateway_controller:
            logger.info('Attack received - %s', attack)

            conditions = {'mac': attack['src_mac']}
            logger.debug('Created conditions - [%s]', conditions)
            values = self.topo.get('hosts').values()
            logger.debug('Creating host with values - [%s]', values)
            host = list(filter(
                lambda item: all(
                    (item[k] == v for (k, v) in conditions.items())),
                values))

            logger.debug(
                'Check the hosts and register the attack with host object '
                '- [%s]', host)
            logger.debug('host.__class__ - [%s]', host.__class__)
            if len(host) > 0:
                logger.debug('host len is - [%s]', len(host))
                return host[0], gateway_controller
            else:
                logger.error('No Device Matches MAC [%s]',
                             attack.get('src_mac'))
        else:
            logger.warning('No Gateway Controller call')

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
