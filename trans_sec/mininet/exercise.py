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
import json
import logging
import os
import subprocess
import threading
from time import sleep

from mininet.cli import CLI
from mininet.link import TCLink, Intf
from mininet.net import Mininet
from mininet.topo import Topo

from trans_sec.device_software.device_daemon import (
    AttackDaemon, HeartbeatDaemon, SniffAndLogDaemon)
from trans_sec.mininet.p4_mininet import P4Host, P4Switch
from trans_sec.controller import simple_controller
from trans_sec.p4runtime_lib.p4runtime_switch import P4RuntimeSwitch

logger = logging.getLogger('exercise')


def configure_p4_switch(**switch_args):
    """ Helper class that is called by mininet to initialize
        the virtual P4 switches. The purpose is to ensure each
        switch's thrift server is using a unique port.
    """
    if "sw_path" in switch_args and 'grpc' in switch_args['sw_path']:
        # If grpc appears in the BMv2 switch target, will start P4 Runtime
        class ConfiguredP4RuntimeSwitch(P4RuntimeSwitch):
            def __init__(self, *opts, **kwargs):
                kwargs.update(switch_args)
                P4RuntimeSwitch.__init__(self, *opts, **kwargs)

            def describe(self):
                logger.info("%s -> gRPC port: %s", self.name, self.grpc_port)

        return ConfiguredP4RuntimeSwitch
    else:
        class ConfiguredP4Switch(P4Switch):
            next_thrift_port = 9090

            def __init__(self, *opts, **kwargs):
                global next_thrift_port
                kwargs.update(switch_args)
                kwargs['thrift_port'] = ConfiguredP4Switch.next_thrift_port
                ConfiguredP4Switch.next_thrift_port += 1
                P4Switch.__init__(self, *opts, **kwargs)

            def describe(self):
                logger.info(
                    "%s -> Thrift port: %s", self.name, self.thrift_port)

        return ConfiguredP4Switch


class ExerciseTopo(Topo):
    """ The mininet topology class for the P4 tutorial exercises.
        A custom class is used because the exercises make a few topology
        assumptions, mostly about the IP and MAC addresses.
    """

    def __init__(self, hosts, switches, links, log_dir, **opts):
        Topo.__init__(self, **opts)
        self.sw_port_mapping = {}

        for sw_name, sw in switches.items():
            dpid = self.__int_to_dpid(sw['id'])
            self.addSwitch(sw['name'], dpid=dpid,
                           log_file="%s/%s.log" % (log_dir, sw))

        for link in links:
            np = link.get('north_facing_port')
            sp = link.get('south_facing_port')

            # Two switches
            if np and sp:
                s_switch = switches.get(link.get('south_node'))
                n_switch = switches.get(link.get('north_node'))

                self.addLink(s_switch.get('name'), n_switch.get('name'),
                             delay=link['latency'], bw=link['bandwidth'],
                             addr1=s_switch.get('mac'),
                             addr2=n_switch.get('mac'))
                self.add_switch_port(s_switch.get('name'),
                                     n_switch.get('name'),
                                     link.get('north_facing_port'))
                self.add_switch_port(n_switch.get('name'),
                                     s_switch.get('name'),
                                     link.get('south_facing_port'))
                logger.info('Adding Switch Link %s %s port:%d <--> port:%d' % (
                    link['south_node'], link['north_node'],
                    link['north_facing_port'], link['south_facing_port']))

            # South switch has a north facing port
            elif np:
                s_switch = switches.get(link.get('south_node'))
                n_host = hosts.get(link.get('north_node'))

                # ignore externals
                if n_host is not None:
                    self.addHost(n_host.get('name'),
                                 ip=n_host.get('ip') + '/24',
                                 mac=n_host.get('mac'))
                    self.addLink(n_host.get('name'), s_switch.get('name'),
                                 delay=link['latency'], bw=link['bandwidth'],
                                 addr1=n_host.get('mac'),
                                 addr2=s_switch.get('mac'))
                    self.add_switch_port(s_switch.get('name'),
                                         n_host.get('name'), np)
                    logger.info(
                        "Adding host %s link %s %s to switch %s %s on port %s",
                        n_host.get('name'), n_host.get('ip'),
                        n_host.get('mac'), s_switch.get('name'),
                        s_switch.get('mac'), np)
            # North switch has a south facing port to the host
            elif sp is not None:
                n_switch = switches.get(link.get('north_node'))
                s_host = hosts.get(link.get('south_node'))

                # ignore externals
                if s_host is not None:
                    self.addHost(s_host.get('name'),
                                 ip=s_host.get('ip') + '/24',
                                 mac=s_host.get('mac'))
                    self.addLink(s_host.get('name'), n_switch.get('name'),
                                 delay=link['latency'], bw=link['bandwidth'],
                                 addr1=s_host.get('mac'),
                                 addr2=n_switch.get('mac'))
                    self.add_switch_port(n_switch.get('name'),
                                         s_host.get('name'), sp)

                    logger.info("Adding host %s link %s %s to switch %s %s on "
                                "port %d",
                                s_host.get('name'), s_host.get('ip'),
                                s_host.get('mac'), n_switch.get('name'),
                                n_switch.get('mac'), sp,)
            else:
                logger.info('Error in link.  At least one port must be '
                            'defined %s', link)

            self.print_port_mapping()

    @staticmethod
    def __int_to_dpid(dpid):
        try:
            dpid = hex(dpid)[2:]
            dpid = '0' * (16 - len(dpid)) + dpid
            return dpid
        except IndexError:
            raise Exception('Unable to derive default data path ID - '
                            'please either specify a dpid or use a '
                            'canonical switch name such as s23.')

    def add_switch_port(self, sw, target, port=None):
        if sw not in self.sw_port_mapping:
            self.sw_port_mapping[sw] = []
        if port is None:
            port_num = len(self.sw_port_mapping[sw]) + 1
            self.sw_port_mapping[sw].append((port_num, target))
        else:
            self.sw_port_mapping[sw].append((port, target))

    def print_port_mapping(self):
        logger.info("Switch port mapping:")
        for sw in sorted(self.sw_port_mapping.keys()):
            logger.info("%s: " % sw,)
            for port_num, target in self.sw_port_mapping[sw]:
                logger.info("%d:%s\t" % (port_num, target),)


class ExerciseRunner:
    """
        Attributes:
            log_dir  : string   // directory for mininet log files
            pcap_dir : string   // directory for mininet switch pcap files
            quiet    : bool     // determines if we print logger messages

            hosts    : list<string>       // list of mininet host names
            switches : dict<string, dict> // mininet host names and their
                                             associated properties
            links    : list<dict>         // list of mininet link properties

            switch_json : string // json of the compiled p4 example
            bmv2_exe    : string // name or path of the p4 switch binary

            topo : Topo object   // The mininet topology instance
            mininet : Mininet object // The mininet instance
    """

    def __init__(self, topo_file, log_dir, pcap_dir,
                 switch_json, devices_conf, dashboard_url,
                 bmv2_exe='simple_switch', quiet=False, run_daemon=False):
        """ Initializes some attributes and reads the topology json. Does not
            actually run the exercise. Use run_exercise() for that.

            Arguments:
                topo_file : string    // A json file which describes the
                                         exercise's mininet topology.
                log_dir  : string     // Path to a directory for storing
                                         exercise logs
                pcap_dir : string     // Same for mininet switch pcap files
                switch_json : string  // Path to a compiled p4 json for bmv2
                devices_conf : string  // Path to devices configuration
                dashboard_url : string  // PDP dashboard url
                bmv2_exe    : string  // Path to the p4 behavioral binary
                quiet : bool          // Enable/disable script debug messages
        """

        self.quiet = quiet
        logger.info('Reading topology file [%s]', topo_file)
        with open(topo_file, 'r') as f:
            self.topo_file = json.load(f)
        self.hosts = self.topo_file['hosts']
        self.switches = self.topo_file['switches']
        self.external = self.topo_file.get('external')
        self.links = self.topo_file['links']
        self.topo = None
        self.mininet = None

        # Ensure all the needed directories exist and are directories
        for dir_name in [log_dir, pcap_dir]:
            if not os.path.isdir(dir_name):
                if os.path.exists(dir_name):
                    raise Exception(
                        "'%s' exists and is not a directory!" % dir_name)
                os.mkdir(dir_name)
        self.log_dir = log_dir
        self.pcap_dir = pcap_dir
        self.switch_json = switch_json
        self.devices_conf = devices_conf
        self.dashboard_url = dashboard_url
        self.bmv2_exe = bmv2_exe
        self.run_daemon = run_daemon
        self.daemons = []

    def run_exercise(self):
        """ Sets up the mininet instance, programs the switches,
            and starts the mininet CLI. This is the main method to run after
            initializing the object.
        """
        # Initialize mininet with the topology specified by the config
        logger.info('Running exercise')
        self.create_network()
        self.add_external_connections()
        self.mininet.start()
        sleep(1)

        # some programming that must happen after the net has started
        self.program_hosts()
        self.program_switches()
        threads = []

        # wait for that to finish. Not sure how to do this better
        sleep(1)

        # Create Mininet host daemons
        if self.run_daemon:
            for host_name, dev_confs in self.devices_conf.items():
                if self.hosts.get(host_name):
                    for dev_conf in dev_confs:
                        self.daemons.append(
                            self.__create_daemon(host_name, dev_conf))

            for daemon in self.daemons:
                logger.info('Starting Daemon for %s', daemon.mn_device.name)
                t1 = threading.Thread(target=daemon.start, args=())
                t1.start()
                threads.append(t1)

        self.do_net_cli()
        # stop right after the CLI is exited
        if self.run_daemon:
            for daemon in self.daemons:
                daemon.stop()
            i = 0
            for thread in threads:
                logger.info('Waiting on %s', self.daemons[i].mn_device.name)
                while thread.isAlive():
                    sleep(1)
                i += 1

        self.mininet.stop()

    def __create_daemon(self, host_name, dev_conf):
        """
        Instantiates the configured daemon object
        """
        daemon_type = dev_conf.get('daemon')
        mn_device = None
        for device in self.mininet.hosts:
            if device.name == host_name:
                mn_device = device

        if daemon_type and mn_device:
            device_log_file = '{}/device_{}_{}.log'.format(
                self.log_dir, daemon_type, host_name)
            if daemon_type == 'attack':
                logger.info(
                    'Creating attack daemon for [%s] with dashboard_url [%s]'
                    ' and log file [%s]',
                    host_name, self.dashboard_url, device_log_file)
                return AttackDaemon(
                    dashboard_url=self.dashboard_url,
                    mn_device=mn_device,
                    device_config=dev_conf,
                    log_file=device_log_file,
                    device_log_dir=self.log_dir,
                    level=logging.DEBUG)

            elif daemon_type == 'heartbeat':
                logger.info(
                    'Creating heartbeat daemon for [%s] and log file [%s]',
                    host_name, device_log_file)
                return HeartbeatDaemon(
                    mn_device=mn_device,
                    device_config=dev_conf,
                    log_file=device_log_file,
                    device_log_dir=self.log_dir,
                    level=logging.DEBUG)

            elif daemon_type == 'sniff_and_log':
                logger.info(
                    'Creating sniff and log daemon for [%s] and log file [%s]',
                    host_name, device_log_file)
                return SniffAndLogDaemon(
                    mn_device=mn_device,
                    device_config=dev_conf,
                    log_file=device_log_file,
                    device_log_dir=self.log_dir,
                    level=logging.DEBUG)

    def create_network(self):
        """ Create the mininet network object, and store it as self.mininet.

            Side effects:
                - Mininet topology instance stored as self.topo
                - Mininet instance stored as self.mininet
        """
        logger.info("Building mininet topology.")

        self.topo = ExerciseTopo(self.hosts, self.switches, self.links,
                                 self.log_dir)

        switch_class = configure_p4_switch(
            sw_path=self.bmv2_exe,
            json_path=self.switch_json,
            log_console=True,
            pcap_dump=self.pcap_dir)

        self.mininet = Mininet(topo=self.topo,
                               link=TCLink,
                               host=P4Host,
                               switch=switch_class,
                               controller=None)

    def add_external_connections(self):
        for link in self.links:
            external = self.external.get(link['north_node'])
            if external is not None:
                sw_obj = self.mininet.get(link['south_node'])
                Intf(external.get('id'), node=sw_obj)

    def program_switch_p4runtime(self, sw_dict):
        """ This method will use P4Runtime to program the switch using the
            content of the runtime JSON file as input.
        """
        sw_name = sw_dict['name']
        sw_obj = self.mininet.get(sw_name)
        grpc_port = sw_obj.grpc_port
        device_id = sw_obj.device_id
        outfile = '%s/%s-p4rt-exercise.log' % (self.log_dir, sw_name)
        simple_controller.program_switch(
            addr='127.0.0.1:%d' % grpc_port,
            device_id=device_id,
            p4info_fpath=sw_dict['runtime_p4info'],
            bmv2_json_fpath=sw_dict['runtime_json'],
            proto_dump_fpath=outfile)

    def program_switch_cli(self, sw_name, sw_dict):
        """ This method will start up the CLI and use the contents of the
            command files as input.
        """
        cli = 'simple_switch_CLI'
        # get the port for this particular switch's thrift server
        sw_obj = self.mininet.get(sw_name)
        thrift_port = sw_obj.thrift_port

        cli_input_commands = sw_dict['cli_input']
        logger.info('Configuring switch %s with file %s' % (
            sw_name, cli_input_commands))
        with open(cli_input_commands, 'r') as fin:
            cli_outfile = '%s/%s_cli_output.log' % (self.log_dir, sw_name)
            with open(cli_outfile, 'w') as cli_file:
                subprocess.Popen([cli, '--thrift-port', str(thrift_port)],
                                 stdin=fin, stdout=cli_file)

    def program_switches(self):
        """ This method will program each switch using the BMv2 CLI and/or
            P4Runtime, depending if any command or runtime JSON files were
            provided for the switches.
        """
        for name, sw in self.switches.items():
            if 'cli_input' in sw:
                self.program_switch_cli(sw['name'], sw)
            if 'runtime_json' in sw:
                self.program_switch_p4runtime(sw)

    def program_hosts(self):
        """ Adds static ARP entries and default routes to each mininet host.

            Assumes:
                - A mininet instance is stored as self.mininet and
                  self.mininet.start() has been called.
        """
        for name, host in self.hosts.items():
            h = self.mininet.get(host['name'])
            h_iface = h.intfs.values()[0]
            link = h_iface.link

            sw_iface = link.intf1 if link.intf1 != h_iface else link.intf2
            sw_ip = host['switch_ip']

            # Ensure each host's interface name is unique, or else
            # mininet cannot shutdown gracefully
            h.defaultIntf().rename('%s-eth0' % host['name'])
            # static arp entries and default routes
            h.cmd('arp -i %s -s %s %s' % (h_iface.name, sw_ip, sw_iface.mac))
            h.cmd('ethtool --offload %s rx off tx off' % h_iface.name)
            h.cmd('ip route add %s dev %s' % (sw_ip, h_iface.name))
            h.setDefaultRoute("via %s" % sw_ip)

    def do_net_cli(self):
        """ Starts up the mininet CLI and prints some helpful output.

            Assumes:
                - A mininet instance is stored as self.mininet and
                  self.mininet.start() has been called.
        """
        for s in self.mininet.switches:
            s.describe()
        for h in self.mininet.hosts:
            try:
                h.describe()
            except Exception as e:
                logger.warn("Ignore exception [%s]", e)
        logger.info("Starting mininet CLI")
        # Generate a message that will be printed by the Mininet CLI to make
        # interacting with the simple switch a little easier.
        print('')
        print('==============================================================')
        print('Welcome to the BMV2 Mininet CLI!')
        print('==============================================================')
        print('Your P4 program is installed into the BMV2 software switch')
        print('and your initial configuration is loaded. You can interact')
        print('with the network using the mininet CLI below.')
        print('')
        if self.switch_json:
            print('To inspect or change the switch configuration, connect to')
            print('CLI from your host operating system using this command:')
            print('  simple_switch_CLI --thrift-port <switch thrift port>')
            print('')
        print('To view a switch log, run this command from your host OS:')
        print('  tail -f %s/<switchname>.log' % self.log_dir)
        print('')
        print('To view the switch output pcap, check the pcap files in %s:'
              % self.pcap_dir)
        print(' for example run:  sudo tcpdump -xxx -r s1-eth1.pcap')
        print('')

        CLI(self.mininet)
