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
from mininet.topo import Topo


class AppTopo(Topo):

    def __init__(self, links, latencies, log_dir="/tmp", bws=None, **opts):
        Topo.__init__(self, **opts)

        nodes = sum(map(list, zip(*links)), [])
        host_names = sorted(list(set(filter(lambda n: n[0] == 'h', nodes))))
        sw_names = sorted(list(set(filter(lambda n: n[0] == 's', nodes))))
        sw_ports = dict([(sw, []) for sw in sw_names])

        self.host_links = dict()
        self.sw_links = dict([(sw, {}) for sw in sw_names])

        for sw_name in sw_names:
            self.addSwitch(sw_name, log_file="%s/%s.log" % (log_dir, sw_name))

        for host_name in host_names:
            host_num = int(host_name[1:])

            self.addHost(host_name)

            self.host_links[host_name] = {}
            host_links = filter(
                lambda l: l[0] == host_name or l[1] == host_name, links)

            sw_idx = 0
            for link in host_links:
                sw = link[0] if link[0] != host_name else link[1]
                sw_num = int(sw[1:])
                assert sw[0] ==\
                    's', "Hosts should be connected to switches, "\
                         "not {}".format(str(sw))
                host_ip = "10.0.%d.%d" % (sw_num, host_num)
                host_mac = '00:00:00:00:%02x:%02x' % (sw_num, host_num)
                delay_key = ''.join([host_name, sw])
                delay = latencies[
                    delay_key] if delay_key in latencies else '0ms'
                bw = bws[delay_key] if delay_key in bws else None
                sw_ports[sw].append(host_name)
                self.host_links[host_name][sw] = dict(
                    idx=sw_idx,
                    host_mac=host_mac,
                    host_ip=host_ip,
                    sw=sw,
                    sw_mac="00:00:00:00:%02x:%02x" % (sw_num, host_num),
                    sw_ip="10.0.%d.%d" % (sw_num, 254),
                    sw_port=sw_ports[sw].index(host_name) + 1
                )
                self.addLink(host_name, sw, delay=delay, bw=bw,
                             addr1=host_mac,
                             addr2=self.host_links[host_name][sw]['sw_mac'])
                sw_idx += 1

        for link in links:  # only check switch-switch links
            sw1, sw2 = link
            if sw1[0] != 's' or sw2[0] != 's':
                continue

            delay_key = ''.join(sorted([sw1, sw2]))
            delay = latencies[delay_key] if delay_key in latencies else '0ms'
            bw = bws[delay_key] if delay_key in bws else None

            self.addLink(sw1, sw2, delay=delay, bw=bw)  # ,  max_queue_size=10)
            sw_ports[sw1].append(sw2)
            sw_ports[sw2].append(sw1)

            sw1_num, sw2_num = int(sw1[1:]), int(sw2[1:])
            sw1_port = dict(mac="00:00:00:%02x:%02x:00" % (sw1_num, sw2_num),
                            port=sw_ports[sw1].index(sw2) + 1)
            sw2_port = dict(mac="00:00:00:%02x:%02x:00" % (sw2_num, sw1_num),
                            port=sw_ports[sw2].index(sw1) + 1)

            self.sw_links[sw1][sw2] = [sw1_port, sw2_port]
            self.sw_links[sw2][sw1] = [sw2_port, sw1_port]
