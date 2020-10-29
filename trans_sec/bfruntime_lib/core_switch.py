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

data_inspection_tbl = 'TpsCoreEgress.data_inspection_t'
data_inspection_tbl_key = 'hdr.udp_int.dst_port'
data_inspection_action = 'TpsCoreEgress.data_inspect_packet'
data_inspection_action_val = 'switch_id'

data_fwd_tbl = 'TpsCoreIngress.data_forward_t'
data_fwd_tbl_key = 'hdr.ethernet.dst_mac'
data_fwd_action = 'TpsCoreIngress.data_forward'
data_fwd_action_val = 'port'


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
        self.write_clone_entries(self.sw_info['clone_egress'])
        self.setup_telemetry_rpt()

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

    def write_clone_entries(self, port, mirror_tbl_key=1):
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

    def delete_clone_entries(self, port, mirror_tbl_key=1):
        mirror_cfg_table = self.get_table("$mirror.cfg")
        mirror_cfg_table.entry_del([
            mirror_cfg_table.make_key([KeyTuple('$sid', mirror_tbl_key)])])

    def add_data_inspection(self, dev_id, dev_mac):
        self.insert_table_entry(data_inspection_tbl,
                                data_inspection_action,
                                [KeyTuple(data_inspection_tbl_key,
                                          value=UDP_INT_DST_PORT)],
                                [DataTuple(data_inspection_action_val,
                                           val=int(self.int_device_id))])

    def del_data_inspection(self, dev_id, dev_mac):
        self.delete_table_entry(data_inspection_tbl,
                                [KeyTuple(data_inspection_tbl_key,
                                          value=UDP_INT_DST_PORT)])

    def read_ae_ip(self):
        trpt_table_obj = self.get_table('TpsCoreEgress.setup_telemetry_rpt_t')
        ae_ip = "0.0.0.0"
        if trpt_table_obj:
            try:
                data, key = next(
                    trpt_table_obj.entry_get(self.target, [],
                                             flags={"from_hw": True}))
                table_data = data.to_dict()
                ae_ip = table_data["ae_ip"]
            except Exception as e:
                logger.info("Unable to access table entry info - [%s]", e)
        return ae_ip

    def setup_telemetry_rpt(self, ae_ip=None):

        if ae_ip is None:
            ae_ip = self.read_ae_ip()

        if ae_ip:
            logger.info(
                'Setting up telemetry report on core device [%s] with '
                'AE IP - [%s]', self.device_id, ae_ip)
            ip_addr = ipaddress.ip_address(ae_ip)
            action_name = 'TpsCoreEgress.setup_telem_rpt_ipv{}'.format(
                ip_addr.version)
            try:
                self.insert_table_entry(
                    'TpsCoreEgress.setup_telemetry_rpt_t',
                    action_name,
                    [KeyTuple('hdr.udp_int.dst_port',
                              value=UDP_INT_DST_PORT)],
                    [DataTuple('ae_ip',
                               val=bytearray(ip_addr.packed))])
            except Exception as e:
                if 'ALREADY_EXISTS' in str(e):
                    pass
                else:
                    raise e
        else:
            logger.warning('AE IP not found cannot setup telemetry report')
