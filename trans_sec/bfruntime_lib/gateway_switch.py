# Copyright (c) 2020 Cable Television Laboratories, Inc.
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
#
# Originally copied from:
#
# Copyright 2017-present Open Networking Foundation
#
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
#
import logging
from abc import ABC

from trans_sec.bfruntime_lib.bfrt_switch import BFRuntimeSwitch

logger = logging.getLogger('gateway_switch')


class GatewaySwitch(BFRuntimeSwitch, ABC):
    def __init__(self, sw_info, proto_dump_file=None):
        """
        Construct Switch class to control BMV2 switches running gateway.p4
        """
        super(self.__class__, self).__init__(sw_info, proto_dump_file)
        self.nat_udp_ports = set()
        self.nat_tcp_ports = set()
        self.tcp_port_count = 1
        self.udp_port_count = 1

    def add_data_inspection(self, dev_id, dev_mac):
        raise NotImplementedError

    def write_multicast_entry(self, hosts):
        raise NotImplementedError
