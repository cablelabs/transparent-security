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
import logging
import sys
import unittest
import mock
import pkg_resources
import yaml

from trans_sec.p4runtime_lib.bmv2 import GatewaySwitch

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logger = logging.getLogger('gateway_switch_tests')


class GatewaySwitchTests(unittest.TestCase):
    """
    Tests for the CoreController class
    """

    def setUp(self):
        topo_file = pkg_resources.resource_filename(
            'tests.trans_sec.conf', 'gateway-topo.yaml')
        with open(topo_file, 'r') as f:
            topo_dict = yaml.safe_load(f)

        print(topo_dict)
        self.sw_info = topo_dict['switches']['gateway']
        self.p4_json = pkg_resources.resource_filename(
            'tests.trans_sec.conf', 'gateway.json')

    @mock.patch('trans_sec.p4runtime_lib.helper.P4InfoHelper',
                return_value=mock.Mock())
    def test_build_device_config(self, m1):
        """
        Tests constructor for class CoreController
        """

        switch = GatewaySwitch(p4info_helper=m1, sw_info=self.sw_info)

        device_conf = switch.build_device_config(self.p4_json)
        self.assertIsNotNone(device_conf)
