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

    def test_session(self):
        attack = {
            'src_mac': '00:00:00:00:00',
            'src_ip': '10.0.0.1',
            'dst_ip': '10.1.0.1',
            'dst_port': '1234',
            'packet_size': '12',
            'attack_type': 'test',
        }
        ret_val = requests.post(url='http://127.0.0.1:9998/attack',
                                params=attack)
        self.assertEquals(201, ret_val.status_code)


class TestSDNController:
    def __init__(self):
        pass

    @staticmethod
    def add_attacker(body):
        logging.info('Adding an attacker - [%s]', body)
