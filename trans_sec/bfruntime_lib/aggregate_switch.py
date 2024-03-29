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

from bfrt_grpc.client import KeyTuple, DataTuple

from trans_sec.bfruntime_lib.bfrt_switch import BFRuntimeSwitch
from trans_sec.consts import UDP_INT_DST_PORT

logger = logging.getLogger('aggregate_switch')

data_inspection_tbl = 'TpsAggEgress.data_inspection_t'
data_inspection_tbl_key = 'hdr.ethernet.src_mac'
data_inspection_action = 'TpsAggEgress.data_inspect_packet'
data_inspection_action_val_1 = 'device'
data_inspection_action_val_2 = 'switch_id'

dflt_port_tbl = 'TpsAggIngress.default_port_t'
dflt_port_action = 'TpsAggIngress.get_default_port'
dflt_port_action_val = 'port'

data_fwd_tbl = 'TpsAggIngress.data_forward_t'
data_fwd_tbl_key = 'hdr.ethernet.dst_mac'
data_fwd_action = 'TpsAggIngress.data_forward'
data_fwd_action_val = 'port'

data_drop_tbl = 'TpsAggIngress.data_drop_t'
data_drop_tbl_key_1 = 'hdr.ethernet.src_mac'
data_drop_tbl_key_2 = 'meta.ipv4_addr'
data_drop_tbl_key_3 = 'meta.ipv6_addr'
data_drop_tbl_key_4 = 'meta.dst_port'
data_drop_action = 'TpsAggIngress.data_drop'

add_switch_id_tbl = 'TpsAggEgress.add_switch_id_t'
add_switch_id_tbl_key = 'hdr.udp_int.dst_port'
add_switch_id_action = 'TpsAggEgress.add_switch_id'
add_switch_id_action_val = 'switch_id'


class AggregateSwitch(BFRuntimeSwitch):

    def __init__(self, sw_info, client_id=0, is_master=True):
        """
        Construct Switch class to control BMV2 switches running gateway.p4
        """
        logger.info('Instantiating BFRT AggregateSwitch')
        super(self.__class__, self).__init__(sw_info, client_id, is_master)

    def start(self, ansible_inventory, controller_user):
        super(self.__class__, self).start(ansible_inventory, controller_user)
        self.__set_table_field_annotations()

    def receive_digests(self):
        """
        Runnable method for self.digest_thread
        """
        logger.info("Started listening digest thread on device [%s] with "
                    "name [%s]", self.grpc_addr, self.name)

        arp_learn_filter = self.bfrt_info.learn_get("arp_digest")
        arp_learn_filter.info.data_field_annotation_add("src_mac", "mac")
        arp_learn_filter.info.data_field_annotation_add("port", "bytes")

        while True:
            digest = None
            try:
                digest = self.interface.digest_get()
            except Exception as e:
                if 'Digest list not received' not in str(e):
                    logger.debug('Unexpected error receiving digest - [%s]', e)

            if digest:
                data_list = arp_learn_filter.make_data_list(digest)
                if not data_list or len(data_list) == 0:
                    data_list = arp_learn_filter.make_data_list(digest)

                logger.debug('Digest list - [%s]', data_list)
                for data_item in data_list:
                    data_dict = data_item.to_dict()
                    src_mac = data_dict['src_mac']
                    port = int.from_bytes(data_dict['port'], byteorder='big')
                    logger.info(
                        'Adding df & smac table entries with key - [%s] '
                        'value - [%s]', src_mac, port)
                    try:
                        self.add_data_forward(src_mac, port)
                        logger.debug('Added digest to data_forward_t')
                    except Exception as e:
                        if 'ALREADY_EXISTS' in str(e):
                            logger.debug(
                                'Not inserting digest entry to '
                                'data_forward_t - [%s]', e)
                        else:
                            logger.error(
                                'Unexpected error processing digest for '
                                'data_forward_t - [%s]', e)
                            raise e

    def __set_table_field_annotations(self):
        fwd_table = self.get_table(data_fwd_tbl)
        fwd_table.info.key_field_annotation_add(data_fwd_tbl_key, 'mac')

        inspection_table = self.get_table(data_inspection_tbl)
        inspection_table.info.key_field_annotation_add(data_inspection_tbl_key,
                                                       'mac')

        drop_table = self.get_table(data_drop_tbl)
        drop_table.info.key_field_annotation_add(data_drop_tbl_key_1, 'mac')
        drop_table.info.key_field_annotation_add(data_drop_tbl_key_2, 'ipv4')
        drop_table.info.key_field_annotation_add(data_drop_tbl_key_3, 'ipv6')

    def add_data_inspection(self, dev_id, dev_mac):
        logger.info(
            'Inserting dev_id - [%s] with key mac - [%s] into %s',
            dev_id, dev_mac, data_inspection_tbl)
        self.insert_table_entry(data_inspection_tbl,
                                data_inspection_action,
                                [KeyTuple(data_inspection_tbl_key, dev_mac)],
                                [
                                    DataTuple(data_inspection_action_val_1,
                                              int(dev_id)),
                                    DataTuple(data_inspection_action_val_2,
                                              int(self.int_device_id))
                                ])

    def del_data_inspection(self, dev_id, dev_mac):
        logger.info(
            'Deleting key mac - [%s] from %s',
            dev_id, dev_mac, data_inspection_tbl)
        self.delete_table_entry(data_inspection_tbl,
                                [KeyTuple(data_inspection_tbl_key, dev_mac)])

    def update_default_port(self, dflt_port):
        logger.info('Setting default port to - [%s]', dflt_port)
        dflt_tbl = self.get_table(dflt_port_tbl)
        data = dflt_tbl.make_data(
            [DataTuple(dflt_port_action_val, int(dflt_port))],
            dflt_port_action)
        dflt_tbl.default_entry_set(self.target, data)

    def add_data_forward(self, dst_mac, ingress_port):
        logger.info(
            'Inserting port - [%s] with key - [%s] into %s',
            int(ingress_port), dst_mac, data_fwd_tbl)
        self.insert_table_entry(data_fwd_tbl,
                                data_fwd_action,
                                [KeyTuple(data_fwd_tbl_key, dst_mac)],
                                [DataTuple(data_fwd_action_val,
                                           int(ingress_port))])

    def del_data_forward(self, dst_mac):
        logger.info(
            'Deleting table entry with key - [%s] from %s',
            dst_mac, data_fwd_tbl)
        self.delete_table_entry(data_fwd_tbl,
                                [KeyTuple(data_fwd_tbl_key, value=dst_mac)])

    def add_attack(self, **attack):
        logger.info('Aggregate Switch adding attack [%s]', attack)
        action_name, dst_ipv4, dst_ipv6 = self.parse_attack(**attack)
        self.insert_table_entry(data_drop_tbl,
                                data_drop_action,
                                [
                                    KeyTuple(data_drop_tbl_key_1,
                                             attack['src_mac']),
                                    KeyTuple(data_drop_tbl_key_2, dst_ipv4),
                                    KeyTuple(data_drop_tbl_key_3, dst_ipv6),
                                    KeyTuple(data_drop_tbl_key_4,
                                             int(attack['dst_port']))
                                ], [])
        logger.info('Added attack without error - [%s]', attack)

    def stop_attack(self, **kwargs):
        logger.info('Stopping attack [%s]', kwargs)
        action_name, dst_ipv4, dst_ipv6 = self.parse_attack(**kwargs)
        self.delete_table_entry(data_drop_tbl,
                                [
                                    KeyTuple(data_drop_tbl_key_1,
                                             kwargs['src_mac']),
                                    KeyTuple(data_drop_tbl_key_2, dst_ipv4),
                                    KeyTuple(data_drop_tbl_key_3, dst_ipv6),
                                    KeyTuple(data_drop_tbl_key_4,
                                             int(kwargs['dst_port']))
                                ])

    def get_drop_pkt_counts(self):
        logger.info('Requesting drop packets')
        drop_table_obj = self.get_table(data_drop_tbl)
        out_tuples = list()
        if drop_table_obj:
            try:
                entries = drop_table_obj.entry_get(
                    self.target, [], flags={"from_hw": True})
                logger.info("Drop entries class - [%s]", entries.__class__)
                this_entry = next(entries)
                while this_entry:
                    data_dict = this_entry[0].to_dict()
                    keys_dict = this_entry[1].to_dict()
                    logger.info('Drop data - [%s]', data_dict)
                    logger.info('Key data - [%s]', keys_dict)
                    logger.info("Drop report for data - [%s]", data_dict)
                    drop_count = data_dict["$COUNTER_SPEC_PKTS"]
                    logger.info("Drop count - [%s]", drop_count)
                    table_keys = self.__map_drop_tbl_keys(keys_dict)
                    logger.info("Table keys - [%s]", table_keys)
                    out_tuples.append((table_keys, drop_count))

                    # Get next entry
                    this_entry = next(entries)
            except Exception as e:
                logger.info("Unable to access table entry info - [%s]", e)

        logger.info('Returning values - [%s]', out_tuples)
        return out_tuples

    @staticmethod
    def __map_drop_tbl_keys(match_keys):
        key_hashing_map = dict()
        key_hashing_map['mac'] = match_keys[
            'hdr.ethernet.src_mac']['value']
        key_hashing_map['port'] = match_keys[
            'meta.dst_port']['value']
        key_hashing_map['ip_addr'] = match_keys[
            'meta.ipv4_addr']['value']
        key_hashing_map['ipv6_addr'] = match_keys[
            'meta.ipv6_addr']['value']
        return key_hashing_map

    def add_switch_id(self):
        logger.info(
            'Inserting device ID [%s] into %s table',
            self.int_device_id, add_switch_id_tbl)

        try:
            self.insert_table_entry(add_switch_id_tbl,
                                    add_switch_id_action,
                                    [KeyTuple(add_switch_id_tbl_key,
                                              value=UDP_INT_DST_PORT)],
                                    [DataTuple(add_switch_id_action_val,
                                               val=self.int_device_id)])
        except Exception as e:
            if 'ALREADY_EXISTS' in str(e):
                pass
            else:
                logger.error('Unexpected error inserting into table %s - [%s]',
                             add_switch_id_tbl, e)
                raise e
