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
from datetime import datetime


class PacketTelemetry:
    def __init__(self):
        self.telemetry = {
            'time_stamp': datetime.today().isoformat(),
            'global': {
                'dropped': 0,
                'forwarded': 0
            },
            'by_switch': []
        }
        self.switches = []
        self.hosts = []

    def add_switch(self, sid, mac, name, stype):
        self.switches.append(
            dict(device_mac=mac, device_id=sid, device_type=stype,
                 device_name=name, category='switch',
                 children_dropped=0, children_forwarded=0, children=[],
                 parent=None,
                 dropped=0, forwarded=0, threat_detected=False,
                 threat_type=None,
                 threat_mitigated=False))

    def add_host(self, hid, mac, name, dtype):
        self.hosts.append(
            dict(device_mac=mac, device_id=hid, device_type=dtype,
                 device_name=name, category='host',
                 parent=None,
                 dropped=0, forwarded=0, threat_detected=False,
                 threat_type=None,
                 threat_mitigated=False))

    def add_child(self, sid, hid):
        conditions = {'device_id': sid}
        switch = filter(
            lambda item: all((item[k] == v for (k, v) in conditions.items())),
            self.switches)
        if 0 < len(switch) < 2:
            switch[0]['children'].append(hid)
        else:
            logging.error('Rutt row raggy! No single switch matched the sid ',
                          sid)

        conditions = {'device_id': hid}
        device = filter(
            lambda item: all((item[k] == v for (k, v) in conditions.items())),
            self.hosts)
        if 0 < len(device) < 2:
            device[0]['parent'] = sid
        else:
            device = filter(lambda item: all(
                (item[k] == v for (k, v) in conditions.items())),
                            self.switches)
            if 0 < len(device) < 2:
                device[0]['parent'] = sid
            else:
                logging.error(
                    'Rutt row raggy!  No device or switch matched the hid '
                    '[%s]', hid)

    def reset_total(self):
        self.telemetry['global']['dropped'] = 0
        self.telemetry['global']['forwarded'] = 0
        self.telemetry['time_stamp'] = datetime.today().isoformat()

    def register_attack(self, device_id):
        device = self.get_devices([device_id])
        if device is not None:
            device = device[0]
            device['threat_detected'] = True
            device['threat_type'] = 'UDP Flood'
            device['threat_mitigated'] = True

    def update_device(self, device_id, forwarded=None, dropped=None):
        conditions = {'device_id': device_id}
        device = filter(
            lambda item: all((item[k] == v for (k, v) in conditions.items())),
            self.hosts)
        if len(device) is 0:
            device = filter(lambda item: all(
                (item[k] == v for (k, v) in conditions.items())),
                            self.switches)
        if len(device) is 1:
            device = device[0]
            if forwarded is not None:
                device['forwarded'] = forwarded
            if dropped is not None:
                device['dropped'] = dropped
        else:
            logging.debug('Not a valid device', device_id)

    def total(self):
        self.reset_total()
        for host in self.hosts:
            self.telemetry['global']['forwarded'] += host.get('forwarded')
            self.telemetry['global']['dropped'] += host.get('dropped')

    def get_devices(self, device_id_list):
        devices = filter(
            lambda item: any((item['device_id'] == v for v in device_id_list)),
            self.hosts)
        switches = filter(
            lambda item: any((item['device_id'] == v for v in device_id_list)),
            self.switches)
        return devices + switches

    def get_switch_by_name(self, name):
        for switch in self.switches:
            if switch.get('device_name') == name:
                return switch

    def build_msg(self):
        self.telemetry['time_stamp'] = datetime.today().isoformat()
        self.telemetry['by_switch'] = []
        for switch in self.switches:
            switch_msg = dict(switch_id=switch.get('device_name'),
                              by_device=[])
            devices = self.get_devices(switch.get('children'))
            for device in devices:
                switch_msg['by_device'].append(device)
            self.telemetry['by_switch'].append(switch_msg)
