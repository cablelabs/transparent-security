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
from time import sleep

from trans_sec.controller.http_server_flask import SDNControllerServer
from trans_sec.packet.packet_telemetry import PacketTelemetry

# Logger stuff
logger = getLogger('ddos_sdn_controller')

AGG_CTRL_KEY = 'aggregate'
CORE_CTRL_KEY = 'core'
GATEWAY_CTRL_KEY = 'gateway'


class DdosSdnController:
    """
    SDN controller for quelling DDoS attacks
    """
    def __init__(self, topo, controllers, http_server_port):

        self.topo = topo
        self.packet_telemetry = PacketTelemetry()
        self.controllers = controllers
        self.http_server = SDNControllerServer(self, http_server_port)
        self.running = False

    def start(self):
        logger.info('Starting Controllers - [%s]', self.controllers)
        for controller in self.controllers.values():
            controller.start()

        self.__make_switch_rules()
        self.__build_skeleton_packet_telemetry()

        logger.info('Starting HTTP server on port - [%s]',
                    self.http_server.port)
        self.http_server.start()

        self.__main_loop()

    def stop(self):
        logger.info('Stopping SDN controller')
        self.running = False
        self.http_server.stop()

    def __make_switch_rules(self):
        """
        Creates the rules for each controller
        :return:
        """
        logger.info('Creating switch rules on #%s different controllers',
                    len(self.controllers))
        for controller in self.controllers.values():
            controller.make_switch_rules()
        logger.debug('Switch rule creation completed')

    def __build_skeleton_packet_telemetry(self):
        logger.info('Building skeleton packet telemetry')
        for host, host_info in self.topo['hosts'].items():
            self.packet_telemetry.add_host(
                host_info['id'], host_info['mac'],
                host_info['name'], host_info['type'])

        for switch, switch_info in self.topo['switches'].items():
            self.packet_telemetry.add_switch(
                switch_info['id'], switch_info['mac'],
                switch_info['name'], switch_info['type'])

        for switch, switch_info in self.topo['switches'].items():
            conditions = {'north_node': switch}
            south_facing_links = filter(
                lambda item: all(
                    (item[k] == v for (k, v) in conditions.items())),
                self.topo.get('links')
            )

            for link in south_facing_links:
                device_name = link.get('south_node')
                if self.topo.get('hosts').get(device_name) is None:
                    if self.topo.get('switches').get(device_name) is None:
                        if self.topo.get('external').get(device_name) is None:
                            logger.warning(
                                'Unknown device type in link %s', device_name)
                        else:
                            logger.info(
                                'Ignoring Externals for packet telemetry')
                    else:
                        device = self.topo.get('switches').get(device_name)
                        self.packet_telemetry.add_child(
                            switch_info['id'], device['id'])
                        logger.debug(
                            'Added Switch %s southbound of %s',
                            device.get('name'), switch_info.get('name'))
                else:
                    device = self.topo.get('hosts').get(device_name)
                    self.packet_telemetry.add_child(
                        switch_info['id'], device['id'])
                    logger.debug(
                        'Added Device %s southbound of %s' %
                        (device.get('name'), switch_info.get('name')))

    def add_attacker(self, attack):
        """
        Adds a device to perform an attack
        :param attack: dict of attack
        """
        if GATEWAY_CTRL_KEY in self.controllers:
            logger.info('Attack received - %s', attack)

            conditions = {'mac': attack['src_mac']}
            values = self.topo.get('hosts').values()
            host = filter(
                lambda item: all(
                    (item[k] == v for (k, v) in conditions.items())),
                values)
            if len(host) != 0:
                host = host[0]
                logger.info('Adding attack to gateways')
                try:
                    self.controllers.get(GATEWAY_CTRL_KEY).add_attacker(
                        attack, host)
                    self.packet_telemetry.register_attack(host['id'])
                except Exception as e:
                    logger.error(
                        'Error adding attacker to host - [%s] with error - '
                        '[%s])', host['name'], e)
            else:
                logger.error('No Device Matches MAC [%s]',
                             attack.get('src_mac'))
        else:
            logger.warn('No Gateway Controller call')

    def __main_loop(self):
        """
        Starts polling thread
        """
        logger.info('Starting thread')
        self.running = True
        try:
            while self.running:
                logger.info('SDN Controller heartbeat')
                sleep(10)
        except KeyboardInterrupt:
            logger.warning(' Shutting down.')
