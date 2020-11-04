#Analytics Guide

The transparent security analytics module uses the following components for data capture and data analysis.

1. Open source python program Espcap for live data capture. ( https://github.com/vichargrave/espcap )
2. Open source distribution of ElasticSearch. ( https://opendistro.github.io/for-elasticsearch-docs/ )

## Requirements
**Espcap** relies on the Elasticsearch Python Client module to index packets in Elasticsearch. The version of the client module must match the version of Elasticsearch you want to use.
### Support for *Elasticsearch 7.x* requires:

1. Python 3.7 (Python 2.7.x not supported)
2. TShark 3.0.1 (included in Wireshark)
3. *Click* module for Python
4. Elasticsearch Python Client module 7.x
5. Elasticsearch 7.x

### Support for  *Elasticsearch 6.x* requires:

1. Requirements 1 - 3 listed above
2. Elasticsearch Python Client module 6.x
3. Elasticsearch 6.x

## Installation
- The current setup in transparent security analytics tofino build environment is configured with an CENTOS AMI which has all the pre-requisites installed.
- To manually setup your CENTOS machine please follow the steps from [INSTALL](setup/INSTALL.md) Guide.

## Running Examples

- To start a live capture on an analytics instance from the network interface `ae-eth0`, get all packets and index them in the Elasticsearch cluster running at localhost:9200 , assuming your present working directory is *espcap*
  ```
  cd espcap/
  sudo python3 src/espcap.py --nic=ae-eth0 --node=localhost:9200 --chunk=100
  ```
The packets get captured and indexed in ElasticSearch under packets-* index.

- Display the following help message:
  ```
  cd espcap/
  espcap.py --help
  Usage: espcap.py [OPTIONS]

  Options:
    --node  TEXT     Elasticsearch IP and port (default=None, dump packets to
                     stdout)
    --nic   TEXT     Network interface for live capture (default=None, if file
                     or dir specified)
    --file  TEXT     PCAP file for file capture (default=None, if nic specified)
    --dir   TEXT     PCAP directory for multiple file capture (default=None, if
                     nic specified)
    --bpf   TEXT     Packet filter for live capture (default=all packets)
    --chunk INTEGER  Number of packets to bulk index (default=1000)
    --count INTEGER  Number of packets to capture during live capture
                     (default=0, capture indefinitely)
    --list           List the network interfaces
    --help           Show this message and exit.
  ```

## Packet Indexing
Default installation of ElasticSearch cluster is at port 9200 and default installation of Kibana runs at port 5601.

To visualize the indexed packets / incoming data in Kibana you need to create an Index pattern for incoming packets. This is a manual step. Do the following steps for the same.

    1. To access Kibana UI go localhost:5601 => Stack Management => Index Patters => Create index pattern.
    2. Add a name for Index pattern and select the corresponding matching index source.
    3. Click on next step and choose timestamp as primary time field for the index pattern.
    4. Click create index pattern and navigate to Discover tab to see the incoming packets matching the index pattern.









