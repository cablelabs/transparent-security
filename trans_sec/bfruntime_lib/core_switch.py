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
import ipaddress
import logging

from bfrt_grpc.client import KeyTuple, DataTuple

from trans_sec.bfruntime_lib.bfrt_switch import BFRuntimeSwitch
from trans_sec.consts import UDP_INT_DST_PORT

logger = logging.getLogger('core_switch')

add_switch_id_tbl = 'TpsCoreEgress.add_switch_id_t'
add_switch_id_tbl_key = 'hdr.udp_int.dst_port'
add_switch_id_action = 'TpsCoreEgress.add_switch_id'
add_switch_id_action_val = 'switch_id'

data_fwd_tbl = 'TpsCoreIngress.data_forward_t'
data_fwd_tbl_key = 'hdr.ethernet.dst_mac'
data_fwd_action = 'TpsCoreIngress.data_forward'
data_fwd_action_val = 'port'

telem_rpt_tbl = 'TpsCoreEgress.setup_telemetry_rpt_t'
telem_rpt_tbl_key = 'hdr.udp_int.dst_port'
telem_rpt_data = 'ae_ip'

trpt_sample_tbl = 'TpsCoreIngress.mirror_sampler'
trpt_sample_key = '$REGISTER_INDEX'
trpt_rate_field = 'TpsCoreIngress.mirror_sampler.rate'


class CoreSwitch(BFRuntimeSwitch):
    def __init__(self, sw_info, client_id=0, is_master=True):
        """
        Construct Switch class to control BMV2 switches running gateway.p4
        """
        logger.info('Instantiating BFRT CoreSwitch')
        super(self.__class__, self).__init__(sw_info, client_id, is_master)

    def start(self):
        super(self.__class__, self).start()
        self.__set_table_field_annotations()
        self.__write_clone_entries(self.sw_info['clone_egress'])

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
            except Exception:
                pass

            if digest:
                logger.info('Processing digest from core switch - [%s]',
                            digest)
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
                            pass
                        else:
                            logger.error(
                                'Unexpected error processing digest for '
                                'data_forward_t - [%s]', e)
                            raise e

    def __set_table_field_annotations(self):
        df_table = self.get_table(data_fwd_tbl)
        df_table.info.key_field_annotation_add(data_fwd_tbl_key, "mac")

    def add_data_forward(self, dst_mac, ingress_port):
        logger.info(
            'Inserting port - [%s] with key - [%s] into '
            'TpsCoreIngress.data_forward_t', ingress_port, dst_mac)
        self.insert_table_entry(data_fwd_tbl,
                                data_fwd_action,
                                [KeyTuple(data_fwd_tbl_key,
                                          value=dst_mac)],
                                [DataTuple(data_fwd_action_val,
                                           val=int(ingress_port))])

    def del_data_forward(self, dst_mac):
        logger.info(
            'Deleting table entry with key - [%s] from %s',
            dst_mac, data_fwd_tbl)
        self.delete_table_entry(data_fwd_tbl,
                                [KeyTuple(data_fwd_tbl_key, value=dst_mac)])

    def __write_clone_entries(self, port, mirror_tbl_key=1):
        logger.info('Start mirroring operations on table [%s] to port [%s]',
                    "$mirror.cfg", port)
        mirror_cfg_table = self.get_table("$mirror.cfg")

        mirror_cfg_table.entry_add(
            self.target,
            [mirror_cfg_table.make_key([KeyTuple('$sid', mirror_tbl_key)])],
            [mirror_cfg_table.make_data([
                DataTuple('$direction', str_val="BOTH"),
                DataTuple('$ucast_egress_port', port),
                DataTuple('$ucast_egress_port_valid', bool_val=True),
                DataTuple('$session_enable', bool_val=True)
            ], '$normal')]
        )

    def delete_clone_entries(self, mirror_tbl_key=1):
        mirror_cfg_table = self.get_table("$mirror.cfg")
        mirror_cfg_table.entry_del([
            mirror_cfg_table.make_key([KeyTuple('$sid', mirror_tbl_key)])])

    def add_switch_id(self):
        logger.info(
            'Inserting device ID [%s] into add_switch_id_t table',
            self.int_device_id)

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
                raise e

    def read_ae_ip(self, port=UDP_INT_DST_PORT):
        trpt_table_obj = self.get_table(telem_rpt_tbl)
        ae_ip = None
        if trpt_table_obj:
            try:
                data, key = next(
                    trpt_table_obj.entry_get(
                        self.target,
                        [KeyTuple(telem_rpt_tbl_key, value=int(port))]))
                table_data = data.to_dict()
                logger.debug("Table [%s] data [%s]", )
                ae_ip = table_data["ae_ip"]
            except Exception as e:
                if 'field_dict' not in str(e):
                    logger.debug("Unable to access table entry info - [%s]", e)
        return ae_ip

    def setup_telemetry_rpt(self, ae_ip, port):
        logger.info(
            'Setting up telemetry report on core device [%s] with '
            'AE IP - [%s]', self.device_id, ae_ip)
        ip_addr = ipaddress.ip_address(ae_ip)
        logger.debug('ip_addr object - [%s]', ip_addr)
        action_name = 'TpsCoreEgress.setup_telem_rpt_ipv{}'.format(
            ip_addr.version)
        try:
            self.insert_table_entry(
                telem_rpt_tbl,
                action_name,
                [KeyTuple(telem_rpt_tbl_key, value=int(port))],
                [DataTuple(telem_rpt_data, val=bytearray(ip_addr.packed))])
        except Exception as e:
            if 'ALREADY_EXISTS' in str(e):
                pass
            else:
                raise e

    def remove_telemetry_rpt(self, ae_ip, port=UDP_INT_DST_PORT):
        logger.info(
            'Removing up telemetry report from core device [%s] with '
            'AE IP - [%s]', self.device_id, ae_ip)
        ip_addr = ipaddress.ip_address(ae_ip)
        logger.debug('ip_addr object - [%s]', ip_addr)
        try:
            self.delete_table_entry(
                telem_rpt_tbl,
                [KeyTuple(telem_rpt_tbl_key, value=port)])
        except Exception as e:
            if 'ALREADY_EXISTS' in str(e):
                pass
            else:
                raise e

    def set_trpt_sampling_value(self, sample_size):
        logger.info(
            'Setting up telemetry report sample size core device [%s] to [%s]',
            self.device_id, sample_size)

        sample_tbl = self.get_table(trpt_sample_tbl)
        sample_tbl.entry_add(
            self.target,
            [sample_tbl.make_key([KeyTuple(trpt_sample_key, 0)])],
            [sample_tbl.make_data([
                DataTuple(trpt_rate_field, sample_size),
            ])]
        )
