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
import logging
import unittest

import pkg_resources

from trans_sec.controller.ddos_sdn_controller import DdosSdnController

logger = logging.getLogger('ddos_sdn_controller_tests')


class HttpSessionTests(unittest.TestCase):
    """
    Unit tests for utility functions in convert.py
    """

    # def setUp(self):
    #     """
    #     Start HTTP server
    #     :return:
    #     """
    #     logging.basicConfig(level=logging.DEBUG)
    #     topo_file = pkg_resources.resource_filename(
    #         'tests.trans_sec.conf', 'test_topology.json')
    #     mock_switch_conf_dir = None
    #     self.controller = DdosSdnController(
    #         topo_file, mock_switch_conf_dir, 9998, 'scenario1', '/tmp')
    #     self.controller.start()
    #
    # def tearDown(self):
    #     self.controller.stop()

    # def test_foo(self):
    #     self.controller.add_attacker({})
