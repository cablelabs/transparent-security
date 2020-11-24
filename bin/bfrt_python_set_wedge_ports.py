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

port = bfrt.port.port
port.add(dev_port=0x00000088, speed="BF_SPEED_10G", port_enable=True, fec="BF_FEC_TYP_NONE")
port.add(dev_port=0x00000090, speed="BF_SPEED_10G", port_enable=True, fec="BF_FEC_TYP_NONE")
port.add(dev_port=0x00000098, speed="BF_SPEED_10G", port_enable=True, fec="BF_FEC_TYP_NONE")