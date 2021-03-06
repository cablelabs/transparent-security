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

from trans_sec.p4runtime_lib.aggregate_switch import AggregateSwitch

logging.basicConfig(stream=sys.stdout, level=logging.DEBUG)
logger = logging.getLogger('aggregate_switch_tests')


class AggregateSwitchTests(unittest.TestCase):
    """
    Tests for the CoreController class
    """

    def setUp(self):
        topo_file = pkg_resources.resource_filename(
            'tests.trans_sec.conf', 'aggregate-topo.yaml')
        with open(topo_file, 'r') as f:
            topo_dict = yaml.safe_load(f)

        print(topo_dict)
        self.sw_info = topo_dict['switches']['aggregate']
        self.p4_json = pkg_resources.resource_filename(
            'tests.trans_sec.conf', 'aggregate.json')

    @mock.patch('trans_sec.p4runtime_lib.helper.P4InfoHelper',
                return_value=mock.Mock())
    @mock.patch(
        'trans_sec.switch.SwitchConnection.build_device_config',
        return_value=mock.Mock())
    def test_construction(self, m1, m2):
        """
        Tests constructor for class CoreController
        """

        switch = AggregateSwitch(sw_info=self.sw_info)
        self.assertIsNotNone(switch)
