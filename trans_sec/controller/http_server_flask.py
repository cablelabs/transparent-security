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
import json
import logging
import threading

import requests
from flask import Flask, request
from flask_restful import reqparse
from flask_restful_swagger_3 import swagger, Resource, Api

logger = logging.getLogger('http_server_handler')


class SDNControllerServer:
    def __init__(self, sdn_controller, port=9998, host='0.0.0.0'):
        logger.info('Starting SDN Controller')
        self.sdn_controller = sdn_controller
        self.port = port
        self.host = host
        self.thread = threading.Thread(target=self.flask_thread)
        self.http_server = Flask('sdn_controller_api_server')
        self.api = Api(self.http_server, title='TPS Controller API',
                       description='APIs for some basic P4 CRUD operations')
        self.server_start = None

    def start(self):
        logger.info('Starting Web services')
        try:
            logger.info('Starting dataForward')
            self.api.add_resource(
                DataForward, '/dataForward',
                resource_class_kwargs={'sdn_controller': self.sdn_controller})

            logger.info('Starting dataInspection')
            self.api.add_resource(
                DataInspection, '/dataInspection',
                resource_class_kwargs={'sdn_controller': self.sdn_controller})

            logger.info('Starting gwAttack')
            self.api.add_resource(
                GwAttack, '/gwAttack',
                resource_class_kwargs={'sdn_controller': self.sdn_controller})

            logger.info('Starting aggAttack')
            self.api.add_resource(
                AggAttack, '/aggAttack',
                resource_class_kwargs={'sdn_controller': self.sdn_controller})

            logger.info('Starting setupTelemRpt')
            self.api.add_resource(
                TelemetryReport, '/setupTelemRpt',
                resource_class_kwargs={'sdn_controller': self.sdn_controller})

            logger.info('Starting telemRptSample')
            self.api.add_resource(
                TelemetryReportSampling, '/telemRptSample',
                resource_class_kwargs={'sdn_controller': self.sdn_controller})

            logger.info('Starting dfltPort')
            self.api.add_resource(
                DefaultPort, '/dfltPort',
                resource_class_kwargs={'sdn_controller': self.sdn_controller})

            logger.info('Starting mcastPorts')
            self.api.add_resource(
                MulticastGroups, '/mcastPorts',
                resource_class_kwargs={'sdn_controller': self.sdn_controller})

            logger.info('Starting shutdown')
            self.api.add_resource(Shutdown, '/shutdown')
        except Exception as e:
            logger.error("Unexpected error", e)
            raise e

        logger.info('Starting API Thread')
        self.thread.start()

        logger.info('All resources started')

    def stop(self):
        try:
            requests.post(url='http://{}:{}/shutdown'.format(
                self.host, self.port))
        except Exception as e:
            logger.warning('Trouble shutting down HTTP server - [%s]', e)

    def flask_thread(self):
        logger.info('Starting server on port [%s]', self.port)
        self.server_start = self.http_server.run(host=self.host,
                                                 port=self.port)


class DataForward(Resource):
    """
    Class for exposing web service to enter a data_forward entry into the P4
    gateway.p4
    """
    parser = reqparse.RequestParser()
    parser.add_argument('device_id', type=int, default=0)
    parser.add_argument('switch_mac', type=str)
    parser.add_argument('dst_mac', type=str)
    parser.add_argument('output_port', type=int)

    def __init__(self, **kwargs):
        logger.info('Starting DataForward context')
        self.sdn_controller = kwargs['sdn_controller']

    @swagger.tags(['dataForwardPost'])
    @swagger.response(response_code=201,
                      description='Added data_forward entry')
    @swagger.reqparser(name='DataForwardParser', parser=parser)
    def post(self):
        logger.info('Data forward entry requested')
        parser = reqparse.RequestParser()
        parser.add_argument('device_id', type=int, default=0)
        parser.add_argument('switch_mac', type=str)
        parser.add_argument('dst_mac', type=str)
        parser.add_argument('output_port', type=int)
        args = self.parser.parse_args()

        logger.info('Data forward args - [%s]', args)
        self.sdn_controller.add_data_forward(args)
        return json.dumps({"success": True}), 201

    @swagger.tags(['dataForwardDelete'])
    @swagger.response(response_code=201,
                      description='Deleted data_forward entry')
    @swagger.reqparser(name='DataForwardParser', parser=parser)
    def delete(self):
        logger.info('Data forward entry to remove')
        args = self.parser.parse_args()

        logger.info('Data forward args - [%s]', args)
        self.sdn_controller.del_data_forward(args)
        return json.dumps({"success": True}), 201


class DataInspection(Resource):
    """
    Class for exposing web service to enter a data_forward entry into the P4
    gateway.p4
    """
    parser = reqparse.RequestParser()
    parser.add_argument('device_id', type=int, default=0)
    parser.add_argument('switch_mac', type=str)
    parser.add_argument('device_mac', type=str)

    def __init__(self, **kwargs):
        logger.info('Starting DataInspection context')
        self.sdn_controller = kwargs['sdn_controller']

    @swagger.tags(['dataInspectionPost'])
    @swagger.response(response_code=201,
                      description='Added data_inspection entry')
    @swagger.reqparser(name='DataInspectionParser', parser=parser)
    def post(self):
        logger.info('Attack requested')
        args = self.parser.parse_args()

        logger.info('args - [%s]', args)
        self.sdn_controller.add_data_inspection(args)
        return json.dumps({"success": True}), 201

    @swagger.tags(['dataInspectionDelete'])
    @swagger.response(response_code=201,
                      description='Deleted data_inspection deletion')
    @swagger.reqparser(name='DataInspectionParser', parser=parser)
    def delete(self):
        logger.info('Attacker to remove')
        args = self.parser.parse_args()

        logger.info('args - [%s]', args)
        self.sdn_controller.del_data_inspection(args)
        return json.dumps({"success": True}), 201


class GwAttack(Resource):
    """
    Class for exposing web service to issue an attack call to gateway.p4
    """

    parser = reqparse.RequestParser()
    parser.add_argument('src_mac', type=str)
    parser.add_argument('src_ip', type=str)
    parser.add_argument('dst_ip', type=str)
    parser.add_argument('dst_port', type=str)
    parser.add_argument('packet_size', type=str)
    parser.add_argument('attack_type', type=str)

    def __init__(self, **kwargs):
        logger.info('Starting GwAttack context')
        self.sdn_controller = kwargs['sdn_controller']

    @swagger.tags(['gatewayAttackStart'])
    @swagger.response(response_code=201,
                      description='Mitigated attack on gateway')
    @swagger.reqparser(name='GwAttackParser', parser=parser)
    def post(self):
        logger.info('Attack requested')
        args = self.parser.parse_args()

        logger.info('args - [%s]', args)
        self.sdn_controller.add_attacker(args)
        return json.dumps({"success": True}), 201

    @swagger.tags(['gatewayAttackStop'])
    @swagger.response(response_code=201,
                      description='Unmitigated attacks from gateway')
    @swagger.reqparser(name='GwAttackParser', parser=parser)
    def delete(self):
        logger.info('Attacker to remove')
        args = self.parser.parse_args()

        logger.info('args - [%s]', args)
        self.sdn_controller.remove_attacker(args)
        return json.dumps({"success": True}), 201


class AggDataForward(Resource):
    """
    Class for exposing web service to enter a data_forward entry into the P4
    aggregate.p4
    """
    parser = reqparse.RequestParser()
    parser.add_argument('device_id', type=str, default=0)
    parser.add_argument('dst_mac', type=str)
    parser.add_argument('output_port', type=str)

    def __init__(self, **kwargs):
        logger.info('Starting AggAttack context')
        self.sdn_controller = kwargs['sdn_controller']

    @swagger.tags(['aggDataForwardAdd'])
    @swagger.response(response_code=201,
                      description='Added data forward entry to aggregate')
    @swagger.reqparser(name='AggDataForwardParser', parser=parser)
    def post(self):
        logger.info('Attack requested')
        args = self.parser.parse_args()

        logger.info('args - [%s]', args)
        self.sdn_controller.add_agg_data_forward(args)
        return json.dumps({"success": True}), 201

    @swagger.tags(['aggDataForwardDelete'])
    @swagger.response(response_code=201,
                      description='Deleted data forward entry from aggregate')
    @swagger.reqparser(name='AggDataForwardParser', parser=parser)
    def delete(self):
        logger.info('Attacker to remove')
        args = self.parser.parse_args()

        logger.info('args - [%s]', args)
        self.sdn_controller.del_agg_data_forward(args)
        return json.dumps({"success": True}), 201


class AggAttack(Resource):
    """
    Class for exposing web service to issue an attack call to aggregate.p4
    """
    parser = reqparse.RequestParser()
    parser.add_argument('src_mac', type=str)
    parser.add_argument('dst_ip', type=str)
    parser.add_argument('dst_port', type=str)

    def __init__(self, **kwargs):
        logger.info('Starting AggAttack context')
        self.sdn_controller = kwargs['sdn_controller']

    @swagger.tags(['aggAttackStart'])
    @swagger.response(response_code=201,
                      description='Mitigated attacks from aggregate')
    @swagger.reqparser(name='AggAttackParser', parser=parser)
    def post(self):
        logger.info('Attack requested')
        args = self.parser.parse_args()

        logger.info('args - [%s]', args)
        self.sdn_controller.add_agg_attacker(args)
        return json.dumps({"success": True}), 201

    @swagger.tags(['aggAttackStop'])
    @swagger.response(response_code=201,
                      description='Unmitigated attacks from aggregate')
    @swagger.reqparser(name='AggAttackParser', parser=parser)
    def delete(self):
        logger.info('Attacker to remove')
        args = self.parser.parse_args()

        logger.info('args - [%s]', args)
        self.sdn_controller.remove_agg_attacker(args)
        return json.dumps({"success": True}), 201


class CoreDataForward(Resource):
    """
    Class for exposing web service to enter a data_forward entry into the P4
    core.p4
    """
    parser = reqparse.RequestParser()
    parser.add_argument('device_id', type=str, default=0)
    parser.add_argument('dst_mac', type=str)
    parser.add_argument('output_port', type=str)

    @swagger.tags(['coreDataForwardAdd'])
    @swagger.response(response_code=201,
                      description='Added data forward entry to core')
    @swagger.reqparser(name='CoreDataForwardParser', parser=parser)
    def post(self):
        logger.info('Attack requested')
        args = self.parser.parse_args()

        logger.info('args - [%s]', args)
        self.sdn_controller.add_core_data_forward(args)
        return json.dumps({"success": True}), 201

    @swagger.tags(['coreDataForwardDel'])
    @swagger.response(response_code=201,
                      description='Deleted data forward entry from core')
    @swagger.reqparser(name='CoreDataForwardParser', parser=parser)
    def delete(self):
        logger.info('Attacker to remove')
        args = self.parser.parse_args()

        logger.info('args - [%s]', args)
        self.sdn_controller.del_agg_data_forward(args)
        return json.dumps({"success": True}), 201


class TelemetryReport(Resource):
    """
    Class for exposing web service to issue an attack call to aggregate.p4
    """
    parser = reqparse.RequestParser()
    parser.add_argument('device_id', type=int, default=0)
    parser.add_argument('switch_mac', type=str)
    parser.add_argument('port', type=str)
    parser.add_argument('ae_ip', type=str)
    parser.add_argument('ae_mac', type=str)

    def __init__(self, **kwargs):
        logger.info('Starting TelemetryReport context')
        self.sdn_controller = kwargs['sdn_controller']

    @swagger.tags(['telemetryRptAdd'])
    @swagger.response(response_code=201,
                      description='Configure endpoint for Telemetry Report')
    @swagger.reqparser(name='TelemRptParser', parser=parser)
    def post(self):
        logger.info('Activating telemetry report')
        args = self.parser.parse_args()

        logger.info('args - [%s]', args)
        self.sdn_controller.activate_telem_rpt(args)
        return json.dumps({"success": True}), 201

    @swagger.tags(['telemetryRptDel'])
    @swagger.response(response_code=201,
                      description='Remove Telemetry Report endpoint config')
    @swagger.reqparser(name='TelemRptParser', parser=parser)
    def delete(self):
        logger.info('Deactivating telemetry report')
        args = self.parser.parse_args()

        logger.info('args - [%s]', args)
        self.sdn_controller.remove_agg_attacker(args)
        return json.dumps({"success": True}), 201


class TelemetryReportSampling(Resource):
    """
    Class for exposing web service to change the Telemetry Report sampling
    value. i.e. When "count" == 0, every INT packet will generate a Telem rpt
                when "count" == 1, every other; 2 - every third etc
    """
    parser = reqparse.RequestParser()
    parser.add_argument('sample', type=int, default=0)

    def __init__(self, **kwargs):
        logger.info('Starting TelemetryReportSampling context')
        self.sdn_controller = kwargs['sdn_controller']

    @swagger.tags(['telemetryRptSample'])
    @swagger.response(response_code=201,
                      description='Configure sampling value for the '
                                  'Telemetry Report')
    @swagger.reqparser(name='TelemRptSampleParser', parser=parser)
    def post(self):
        logger.info('Set Telemetry report sampling value')
        args = self.parser.parse_args()

        logger.info('args - [%s]', args)
        self.sdn_controller.set_trpt_sampling_value(args)
        return json.dumps({"success": True}), 201


class DefaultPort(Resource):
    """
    Class for exposing web service to issue an attack call to aggregate.p4
    """
    parser = reqparse.RequestParser()
    parser.add_argument('device_id', type=int, default=0)
    parser.add_argument('switch_mac', type=str)
    parser.add_argument('port', type=int)

    def __init__(self, **kwargs):
        logger.info('Starting DefaultPort context')
        self.sdn_controller = kwargs['sdn_controller']

    @swagger.tags(['setDefaultPort'])
    @swagger.response(response_code=201,
                      description='Update the default port value')
    @swagger.reqparser(name='DefaultPortParser', parser=parser)
    def post(self):
        logger.info('Update default port')
        args = self.parser.parse_args()

        logger.info('args - [%s]', args)
        self.sdn_controller.update_dflt_port(args)
        return json.dumps({"success": True}), 201


class MulticastGroups(Resource):
    """
    Class for exposing web service to issue an attack call to aggregate.p4
    """
    parser = reqparse.RequestParser()
    parser.add_argument('device_id', type=int, default=0)
    parser.add_argument('switch_mac', type=str)
    parser.add_argument('ports', type=str)

    def __init__(self, **kwargs):
        logger.info('Starting MulticastGroups context')
        self.sdn_controller = kwargs['sdn_controller']

    @swagger.tags(['mcastUpdatePorts'])
    @swagger.response(response_code=201,
                      description='Update the multicast groups')
    @swagger.reqparser(name='McastGrpParser', parser=parser)
    def post(self):
        args = self.parser.parse_args()
        logger.info('Setting mcast ports with args - [%s]', args)

        logger.info('args - [%s]', args)
        self.sdn_controller.update_mcast_grp(args)
        return json.dumps({"success": True}), 201

    @swagger.tags(['mcastPortGet'])
    @swagger.response(response_code=201,
                      description='Retrieve the multicast ports')
    @swagger.reqparser(name='McastGrpParser', parser=parser)
    def get(self):
        logger.info('Retrieving mcast ports')
        args = self.parser.parse_args()

        logger.info('args - [%s]', args)
        ports = self.sdn_controller.get_mcast_grp_ports(args)
        logger.info('Returning port values - [%s]', ports)
        return json.dumps({"success": True, "ports": ports}), 201


class Shutdown(Resource):
    @staticmethod
    def post():
        func = request.environ.get('werkzeug.server.shutdown')
        if func is None:
            raise RuntimeError('Not running with the Werkzeug Server')
        func()
