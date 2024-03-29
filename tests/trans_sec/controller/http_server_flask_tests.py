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
# Unit tests for http_session.py
import time

import requests
import unittest

import logging

from trans_sec.controller.http_server_flask import SDNControllerServer

logging.basicConfig(level=logging.DEBUG)

logger = logging.getLogger('http_server_flask_tests')


class HttpSessionTests(unittest.TestCase):
    """
    Unit tests for utility functions in convert.py
    """

    def setUp(self):
        """
        Start HTTP server
        :return:
        """
        self.http_server = SDNControllerServer(TestSDNController())
        self.http_server.start()

        # TODO - sleeping to wait for the server to start. Look at the
        #  http_server class to see if the start() call can bock
        time.sleep(1)

    def tearDown(self):
        self.http_server.stop()

    def test_agg_attack_url_params(self):

        # Test attack with params
        param_attack = {
            'src_mac': '00:00:00:00:00',
            'dst_ip': '10.1.0.1',
            'dst_port': '1234',
        }
        ret_val = requests.post(url='http://127.0.0.1:9998/aggAttack',
                                params=param_attack)
        self.assertEquals(201, ret_val.status_code)

        json_attack = {'event': param_attack}
        ret_val = requests.post(url='http://127.0.0.1:9998/aggAttack',
                                json=json_attack)
        self.assertEquals(201, ret_val.status_code)

        ret_val = requests.post(url='http://127.0.0.1:9998/aggAttack',
                                json=param_attack)
        self.assertEquals(201, ret_val.status_code)


class TestSDNController:
    def __init__(self):
        pass

    @staticmethod
    def add_attacker(body):
        logging.info('Adding an attacker - [%s]', body)

    @staticmethod
    def remove_attacker(body):
        logging.info('Removing an attacker - [%s]', body)

    @staticmethod
    def add_agg_attacker(body):
        logging.info('Adding an attacker - [%s]', body)

    @staticmethod
    def remove_agg_attacker(body):
        logging.info('Removing an attacker - [%s]', body)
