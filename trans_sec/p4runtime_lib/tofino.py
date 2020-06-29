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
import struct
from abc import ABC

from p4.tmp import p4config_pb2

from trans_sec.p4runtime_lib.switch import SwitchConnection

logger = logging.getLogger('tofino')


class TofinoSwitchConnection(SwitchConnection, ABC):
    def build_device_config(self, **kwargs):
        return self.__build_device_config(**kwargs)

    @staticmethod
    def __build_device_config(prog_name, bin_path, cxt_json_path):
        """
        Builds the device config for Tofino
        """
        logger.info(
            'Building device configuration for program - [%s], bin_path - [%s]'
            ', and cxt_json_path - [%s]', prog_name, bin_path, cxt_json_path)
        prog_name = prog_name.encode('utf-8')
        device_config = p4config_pb2.P4DeviceConfig()
        device_config.reassign = True
        with open(bin_path, 'rb') as bin_f:
            with open(cxt_json_path, 'r') as cxt_json_f:
                device_config.device_data = ""
                device_config.device_data += struct.pack("<i", len(prog_name))
                device_config.device_data += prog_name
                tofino_bin = bin_f.read()
                device_config.device_data += struct.pack("<i", len(tofino_bin))
                device_config.device_data += tofino_bin
                cxt_json = cxt_json_f.read()
                device_config.device_data += struct.pack("<i", len(cxt_json))
                device_config.device_data += cxt_json

        return device_config
