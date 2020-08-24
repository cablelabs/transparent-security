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
from abc import ABC

from tofino.bfrt_grpc import bfruntime_pb2

from trans_sec.bfruntime_lib.bfrt_switch import BFRuntimeSwitch

logger = logging.getLogger('core_switch')


class CoreSwitch(BFRuntimeSwitch, ABC):
    def __init__(self, sw_info, proto_dump_file=None):
        """
        Construct Switch class to control BMV2 switches running gateway.p4
        """
        logger.info('Instantiating BFRT CoreSwitch')
        super(self.__class__, self).__init__(sw_info, proto_dump_file)

    def add_data_inspection(self, dev_id, dev_mac):
        logger.info('Adding data inspection to switch ID [%s] and MAC [%s]',
                    dev_id, dev_mac)
        raise NotImplementedError

    def add_switch_id(self, dev_id):
        pass

    def setup_telemetry_rpt(self, ae_ip):
        logger.info(
            'Setting up telemetry report on core device [%s] with '
            'AE IP - [%s]', self.device_id, ae_ip)

        write_req = bfruntime_pb2.WriteRequest()
        self.add_target_data_to_request(write_req)

        update = write_req.updates.add()
        update.type = bfruntime_pb2.Update.INSERT
        table_operation = update.entity.table_operation
        table_name = '{}.setup_telemetry_rpt_t'.format('TofinoCoreEgress')
        table_operation.table_id = self.get_table(table_name)
        # table_operation.table_operations_type = table_op

        return self.write(write_req)

        # table_entry = self.p4info_helper.build_table_entry(
        #     table_name='{}.arp_flood_t'.format(self.p4_ingress),
        #     match_fields={'hdr.ethernet.dst_mac': 'ff:ff:ff:ff:ff:ff'},
        #     action_name='{}.arp_flood'.format(self.p4_ingress),
        #     action_params={})
        # self.write_table_entry(table_entry)
        #
        # ae_ip_addr = socket.gethostbyname(ae_ip)
        # logger.info(
        #     'Starting telemetry report for INT headers with dst_port '
        #     'value of 555 to AE IP [%s]', ae_ip_addr)
        # table_name = '{}.setup_telemetry_rpt_t'.format('TofinoCoreEgress')
        # action_name = '{}.setup_telem_rpt_ipv4'.format('TofinoCoreEgress')
        # match_fields = {
        #     'hdr.udp_int.dst_port': 555
        # }
        # action_params = {
        #     'ae_ip': ae_ip_addr
        # }
        # table_entry = self.p4info_helper.build_table_entry(
        #     table_name=table_name,
        #     match_fields=match_fields,
        #     action_name=action_name,
        #     action_params=action_params)
        # self.write_table_entry(table_entry)
