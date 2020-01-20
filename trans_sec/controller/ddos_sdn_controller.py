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
from datetime import datetime
from logging import getLogger
from time import sleep

from dateutil import parser

from trans_sec.controller.aggregate_controller import AggregateController
from trans_sec.controller.core_controller import CoreController
from trans_sec.controller.gateway_controller import GatewayController
from trans_sec.packet.packet_telemetry import PacketTelemetry
from trans_sec.controller.http_server_flask import SDNControllerServer

# Logger stuff
logger = getLogger('ddos_sdn_controller')

AGG_CTRL_KEY = 'aggregate'
CORE_CTRL_KEY = 'core'
GATEWAY_CTRL_KEY = 'gateway'
TELEMETRY_DELAY = 2.0


class DdosSdnController:
    """
    SDN controller for quelling DDoS attacks
    """
    def __init__(self, topo, platform, switch_config_dir, http_server_port,
                 log_dir, load_p4=True):

        self.topo = topo
        self.switch_config_dir = switch_config_dir
        self.packet_telemetry = PacketTelemetry()

        # Init switch controllers
        self.controllers = {
            GATEWAY_CTRL_KEY: GatewayController(
                platform, self.switch_config_dir, self.topo, log_dir, load_p4),
            AGG_CTRL_KEY: AggregateController(
                platform, self.switch_config_dir, self.topo, log_dir, load_p4),
            CORE_CTRL_KEY: CoreController(
                platform, self.switch_config_dir, self.topo, log_dir, load_p4),
        }

        self.http_server = SDNControllerServer(self, http_server_port)
        self.last_scenario_time = datetime.now()
        self.last_attack_time = datetime.now()
        self.attack = dict(
            active=False, durationSec=0, attackStart=datetime.now(),
            attackEnd=datetime.now(), attackType=None)

    def start(self):
        logger.info('Starting Controllers')
        for controller in self.controllers.values():
            controller.start()

        self.__make_switch_rules()
        self.__build_skeleton_packet_telemetry()

        logger.info('Starting HTTP server on port - [%s]',
                    self.http_server.port)
        self.http_server.start()

        self.__main_loop()

    def stop(self):
        self.http_server.stop()

    def __check_scenario(self):
        """
         GET /state
        RSP {
          mitigation {
            activeScenario: "scenario2"
            timeActivated":"2019-04-29T19:03:56+00:00"
          },
          attack: {
            active: bool
            attackType: "UDP Flood" | "SYN Flood" | ""
            attackStart: timestamp | ""
            attackEnd: timestamp | ""
            durationSec: 30
          }
        }

        Start Idle
        -> Get Scenario 2 from /state
        --> Attack start time 0 end time 60
        --> SDN wipes table entries
        --> SDN sets scenario flag for aggregate mitigation only
        ---> Device 1 gets /state from SDN
        ---> Device 2 gets /state from SDN
        ...
        ---> Device N gets /state from SDN
        ---> Device 1 starts attack
        ...
        ---> Device N starts attack
        --> All attacks end after time 60
        -> SDN gets /state
        --> If mitigation changes scenario or timestamp, repeat line 3 down
        --> Else if attack is true and start_time changed, repeat line 6 down
        --> Else do repeat line 14
        :return:
        """
        # Check if attack is still active
        if self.attack.get('active'):
            logger.debug('Attack is active')
            now = datetime.now().replace(tzinfo=None)
            logger.error(now)
            end = parser.parse(self.attack.get('attackEnd'))
            logger.error(end)
            delta = (end - now).total_seconds()
            if delta <= 0:
                self.attack['active'] = False
        else:
            logger.debug('Attack is inactive')

    def __make_switch_rules(self):
        """
        Creates the rules for each controller
        :return:
        """
        logger.info('Creating switch rules on #%s different controllers',
                    len(self.controllers))
        for controller in self.controllers.values():
            controller.make_switch_rules()

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
        logger.info('Attack received - %s', attack)

        conditions = {'mac': attack['src_mac']}
        values = self.topo.get('hosts').values()
        host = filter(
            lambda item: all(
                (item[k] == v for (k, v) in conditions.items())),
            values)
        if len(host) != 0:
            host = host[0]
            # logger.info('Adding attack to gateway')
            logger.info('Adding attack to aggregate')
            try:
                # self.controllers.get(GATEWAY_CTRL_KEY).add_attacker(
                #     attack, host)
                self.controllers.get(AGG_CTRL_KEY).add_attacker(
                    attack, host, src_mac_hdr_ref='hdr.gw_int.src_mac')
                self.packet_telemetry.register_attack(host['id'])
            except Exception as e:
                logger.error(
                    'Error adding attacker to host - [%s] with error - [%s])',
                    host, e)
        else:
            logger.error('No Device Matches MAC [%s]', attack.get('src_mac'))

    def __main_loop(self):
        """
        Starts polling thread
        """
        logger.info('Starting polling thread')
        try:
            delta = 0.0
            while True:
                sleep_time = TELEMETRY_DELAY - delta
                if sleep_time > 0:
                    sleep(sleep_time)
                start_time = datetime.today()
                self.__check_scenario()
                self.__retrieve_and_send_packet_telemetry()
                current_time = datetime.today()
                delta = (current_time - start_time).total_seconds()
                logger.debug('Telemetry took %f ms' % (delta * 1000))
        except KeyboardInterrupt:
            logger.warning(' Shutting down.')

    def __retrieve_and_send_packet_telemetry(self):
        for controller in self.controllers.values():
            controller.update_all_counters(self.packet_telemetry)
            controller.reset_all_counters(self.packet_telemetry)

    def __send_packet_telemetry(self):
        self.packet_telemetry.total()
        self.packet_telemetry.build_msg()
