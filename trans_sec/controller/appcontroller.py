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
import subprocess

from trans_sec.controller.shortest_path import ShortestPath

logger = logging.getLogger('appcontroller')


class AppController:

    def __init__(self, manifest=None, target=None, topo=None, net=None,
                 links=None):
        self.manifest = manifest
        self.target = target
        self.conf = manifest['targets'][target]
        self.topo = topo
        self.net = net
        self.links = links

    @staticmethod
    def read_entries(filename):
        entries = []
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line == '':
                    continue
                entries.append(line)
        return entries

    @staticmethod
    def add_entries(thrift_port=9090, sw=None, entries=None):
        assert entries
        if sw:
            thrift_port = sw.thrift_port

        p = subprocess.Popen(
            ['simple_switch_CLI', '--thrift-port', str(thrift_port)],
            stdin=subprocess.PIPE)
        p.communicate(input='\n'.join(entries))

    @staticmethod
    def read_register(register, idx, thrift_port=9090, sw=None):
        if sw:
            thrift_port = sw.thrift_port
        p = subprocess.Popen(
            ['simple_switch_CLI', '--thrift-port', str(thrift_port)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        stdout, stderr = p.communicate(
            input="register_read %s %d" % (register, idx))
        reg_val = list(filter(lambda l: ' %s[%d]' % (register, idx) in l,
                              stdout.split('\n')))[0].split('= ', 1)[1]
        return int(reg_val)

    def start(self):
        shortest_path = ShortestPath(self.links)
        entries = {}
        for sw in self.topo.switches():
            entries[sw] = []
            if ('switches' in self.conf
                    and sw in self.conf['switches']
                    and 'entries' in self.conf['switches'][sw]):
                extra_entries = self.conf['switches'][sw]['entries']
                if type(extra_entries) == list:  # array of entries
                    entries[sw] += extra_entries
                else:  # path to file that contains entries
                    entries[sw] += self.read_entries(extra_entries)

        for host_name in self.topo.host_links:
            host = self.net.get(host_name)
            for link in self.topo.host_links[host_name].values():
                iface = host.intfNames()[link['idx']]
                # use mininet to set ip and mac to let it know the change
                host.setIP(link['host_ip'], 24)
                host.setMAC(link['host_mac'])
                host.cmd('arp -i %s -s %s %s' % (
                    iface, link['sw_ip'], link['sw_mac']))
                host.cmd('ethtool --offload %s rx off tx off' % iface)
                host.cmd('ip route add %s dev %s' % (link['sw_ip'], iface))

                # TODO - determine why this was outside of the for block?
                host.setDefaultRoute("via %s" % link['sw_ip'])

        for host in self.net.hosts:
            for sw in self.net.switches:
                path = shortest_path.get(sw.name, host.name,
                                         exclude=lambda n: n[0] == 'h')
                if not path:
                    continue
                if not path[1][0] == 's':
                    continue  # next hop is a switch

            for h2 in self.net.hosts:
                if host == h2:
                    continue
                path = shortest_path.get(host.name, h2.name,
                                         exclude=lambda n: n[0] == 'h')
                if not path:
                    continue
                h_link = self.topo.host_links[host.name][path[1]]
                h2_link = self.topo.host_links[h2.name].values()[0]
                host.cmd('ip route add %s via %s' % (
                    h2_link['host_ip'], h_link['sw_ip']))

        logger.info("Configuring entries in p4 tables")
        for sw_name in entries:
            logger.info("Configuring switch... %s", sw_name)
            sw = self.net.get(sw_name)
            if entries[sw_name]:
                self.add_entries(sw=sw, entries=entries[sw_name])
        logger.info("Configuration complete.")

    def stop(self):
        pass
