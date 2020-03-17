#!/usr/bin/env bash

# Contains the packet generation and sniffing commands for generating INT and non-INT PCAP files

# With INT
sudo python /home/ubuntu/transparent-security/trans_sec/device_software/send_packets.py -y 0 -i 0.005 -it 1 -itd 0 -z gateway1-eth1 -sa 192.168.1.2 -r 10.2.5.2 -sp 9648 -p 3074 -c 1 -e 00:00:00:00:01:01 -s 00:00:00:01:01:00 -pr UDP -m 'UDP INT IPv4'
sudo python /home/ubuntu/transparent-security/trans_sec/device_software/send_packets.py -y 0 -i 0.005 -it 1 -itd 0 -z gateway1-eth1 -sa 192.168.1.2 -r 10.2.5.2 -sp 9648 -p 3074 -c 1 -e 00:00:00:00:01:01 -s 00:00:00:01:01:00 -pr TCP -m 'TCP INT IPv4'

sudo python /home/ubuntu/transparent-security/trans_sec/device_software/send_packets.py -y 0 -i 0.005 -it 1 -itd 0 -z gateway1-eth1 -sa 0000:0000:0000:0000:0000:0001:0001:0002 -r 0000:0000:0000:0000:0000:0002:0001:0002 -sp 9648 -p 3074 -c 1 -e 00:00:00:00:01:01 -s 00:00:00:01:01:00 -pr UDP -m 'UDP INT IPv6'
sudo python /home/ubuntu/transparent-security/trans_sec/device_software/send_packets.py -y 0 -i 0.005 -it 1 -itd 0 -z gateway1-eth1 -sa 0000:0000:0000:0000:0000:0001:0001:0002 -r 0000:0000:0000:0000:0000:0002:0001:0002 -sp 9648 -p 3074 -c 1 -e 00:00:00:00:01:01 -s 00:00:00:01:01:00 -pr TCP -m 'TCP INT IPv6'

# Without INT
sudo python /home/ubuntu/transparent-security/trans_sec/device_software/send_packets.py -y 0 -i 0.005 -it 1 -itd 0 -z gateway1-eth1 -sa 192.168.1.2 -r 10.2.5.2 -sp 9648 -p 3074 -c 1 -e 00:00:00:00:05:05 -s 00:00:00:01:01:00 -pr UDP -m 'UDP Normal IPv4'
sudo python /home/ubuntu/transparent-security/trans_sec/device_software/send_packets.py -y 0 -i 0.005 -it 1 -itd 0 -z gateway1-eth1 -sa 192.168.1.2 -r 10.2.5.2 -sp 9648 -p 3074 -c 1 -e 00:00:00:00:05:05 -s 00:00:00:01:01:00 -pr TCP -m 'TCP Normal IPv4'

sudo python /home/ubuntu/transparent-security/trans_sec/device_software/send_packets.py -y 0 -i 0.005 -it 1 -itd 0 -z gateway1-eth1 -sa 0000:0000:0000:0000:0000:0001:0001:0002 -r 0000:0000:0000:0000:0000:0002:0001:0002 -sp 9648 -p 3074 -c 1 -e 00:00:00:00:05:05 -s 00:00:00:01:01:00 -pr UDP -m 'UDP Normal IPv6'
sudo python /home/ubuntu/transparent-security/trans_sec/device_software/send_packets.py -y 0 -i 0.005 -it 1 -itd 0 -z gateway1-eth1 -sa 0000:0000:0000:0000:0000:0001:0001:0002 -r 0000:0000:0000:0000:0000:0002:0001:0002 -sp 9648 -p 3074 -c 1 -e 00:00:00:00:05:05 -s 00:00:00:01:01:00 -pr TCP -m 'TCP Normal IPv6'


# Commands for sniffing the important interfaces while generating the packets above
sudo tcpdump -i gateway1-eth1 -w gateway1-eth1.pcap
sudo tcpdump -i gateway1-eth2 -w gateway1-eth2.pcap
sudo tcpdump -i aggregate-eth1 -w aggregate-eth1.pcap
sudo tcpdump -i aggregate-eth2 -w aggregate-eth2.pcap
sudo tcpdump -i core-eth2 -w core-eth2.pcap
sudo tcpdump -i core-eth3 -w core-eth3.pcap
