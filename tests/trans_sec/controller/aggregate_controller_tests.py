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
# Unit tests for convert.py
import logging
import mock
import pkg_resources
import unittest

import yaml

from trans_sec.controller.aggregate_controller import AggregateController

logger = logging.getLogger('aggregate_controller_tests')


class AggregateControllerTests(unittest.TestCase):
    """
    Tests for the CoreController class
    """
    def setUp(self):
        # Parse topology file and store into object
        topo_file = pkg_resources.resource_filename(
            'tests.trans_sec.conf', 'test_topology.yaml')
        with open(topo_file, 'r') as f:
            self.topo = yaml.load(f)
            logger.info("Opened file - %s" % f.name)

    @mock.patch('trans_sec.p4runtime_lib.helper.P4InfoHelper',
                return_value=mock.Mock())
    @mock.patch('trans_sec.p4runtime_lib.p4rt_switch.P4RuntimeSwitch',
                return_value=mock.Mock())
    def test_construction(self, m1, m2):
        """
        Tests constructor for class CoreController
        """
        controller = AggregateController('bmv2', 'config_dir', self.topo,
                                         '/tmp')
        self.assertIsNotNone(controller)
