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
        self.controllers = controllers
        self.http_server = SDNControllerServer(self, http_server_port)
        self.running = False

    def start(self, add_di):
        logger.info('Starting Controllers - [%s]', self.controllers)
        for controller in self.controllers.values():
            controller.start()

        logger.debug('Making switch rules with data inspection - [%s]', add_di)
        self.__make_switch_rules(add_di)

        logger.info('Starting HTTP server on port - [%s]',
                    self.http_server.port)
        self.http_server.start()

        self.__main_loop()

    def stop(self):
        logger.info('Stopping SDN controller')
        self.running = False
        self.http_server.stop()

    def __make_switch_rules(self, add_di):
        """
        Creates the rules for each controller
        :return:
        """
        logger.info('Creating switch rules on #%s different controllers',
                    len(self.controllers))
        for controller in self.controllers.values():
            controller.make_switch_rules(add_di)
        logger.debug('Switch rule creation completed')

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
        agg_controller = self.get_agg_controller(attack)
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
        agg_controller = self.get_agg_controller(attack)
        logger.info('Adding attack to aggregate')
        if agg_controller:
            try:
                agg_controller.add_attacker(attack, None)
            except Exception as e:
                logger.error('Error adding attacker with error - [%s])', e)
        else:
            logger.warning('Aggregate controller cannot add attack')

    def get_agg_controller(self, attack):
        agg_controller = self.controllers.get(AGG_CTRL_KEY)
        return agg_controller

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
