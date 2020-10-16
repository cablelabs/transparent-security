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
from flask_restful import Resource, Api, reqparse

logger = logging.getLogger('http_server_handler')


http_server = Flask('sdn_controller_api_server')


class SDNControllerServer:
    def __init__(self, sdn_controller, port=9998, host='0.0.0.0'):
        self.sdn_controller = sdn_controller
        self.port = port
        self.host = host
        self.thread = threading.Thread(target=self.flask_thread)
        self.api = Api(http_server)
        self.server_start = None

    def start(self):
        self.thread.start()
        self.api.add_resource(
            DataForward, '/dataForward',
            resource_class_kwargs={'sdn_controller': self.sdn_controller})
        self.api.add_resource(
            DataInspection, '/dataInspection',
            resource_class_kwargs={'sdn_controller': self.sdn_controller})
        self.api.add_resource(
            GwAttack, '/gwAttack',
            resource_class_kwargs={'sdn_controller': self.sdn_controller})
        self.api.add_resource(
            AggAttack, '/aggAttack',
            resource_class_kwargs={'sdn_controller': self.sdn_controller})
        self.api.add_resource(Shutdown, '/shutdown')

    def stop(self):
        try:
            requests.post(url='http://{}:{}/shutdown'.format(
                self.host, self.port))
        except Exception as e:
            logger.warning('Trouble shutting down HTTP server - [%s]', e)

    def flask_thread(self):
        logger.info('Starting server on port [%s]', self.port)
        self.server_start = http_server.run(host=self.host, port=self.port)


class DataForward(Resource):
    """
    Class for exposing web service to enter a data_forward entry into the P4
    gateway.p4
    """
    def __init__(self, **kwargs):
        self.sdn_controller = kwargs['sdn_controller']
        self.parser = reqparse.RequestParser()
        self.parser.add_argument('device_id', type=int, default=0)
        self.parser.add_argument('dst_mac', type=str)
        self.parser.add_argument('output_port', type=int)
        self.parser.add_argument('switch_mac', type=str)

    def post(self):
        logger.info('Data forward entry requested')
        args = self.parser.parse_args()

        logger.info('Data forward args - [%s]', args)
        self.sdn_controller.add_data_forward(args)
        return json.dumps({"success": True}), 201

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
    def __init__(self, **kwargs):
        self.sdn_controller = kwargs['sdn_controller']
        self.parser = reqparse.RequestParser()
        self.parser.add_argument('device_id', type=int, default=0)
        self.parser.add_argument('switch_mac', type=str)
        self.parser.add_argument('device_mac', type=str)

    def post(self):
        logger.info('Attack requested')
        args = self.parser.parse_args()

        logger.info('Attack args - [%s]', args)
        self.sdn_controller.add_data_inspection(args)
        return json.dumps({"success": True}), 201

    def delete(self):
        logger.info('Attacker to remove')
        args = self.parser.parse_args()

        logger.info('Attack args - [%s]', args)
        self.sdn_controller.del_data_inspection(args)
        return json.dumps({"success": True}), 201


class GwAttack(Resource):
    """
    Class for exposing web service to issue an attack call to gateway.p4
    """
    def __init__(self, **kwargs):
        self.sdn_controller = kwargs['sdn_controller']

        self.parser = reqparse.RequestParser()
        self.parser.add_argument('src_mac', type=str)
        self.parser.add_argument('src_ip', type=str)
        self.parser.add_argument('dst_ip', type=str)
        self.parser.add_argument('dst_port', type=str)
        self.parser.add_argument('packet_size', type=str)
        self.parser.add_argument('attack_type', type=str)

    def post(self):
        logger.info('Attack requested')
        args = self.parser.parse_args()

        logger.info('Attack args - [%s]', args)
        self.sdn_controller.add_attacker(args)
        return json.dumps({"success": True}), 201

    def delete(self):
        logger.info('Attacker to remove')
        args = self.parser.parse_args()

        logger.info('Attack args - [%s]', args)
        self.sdn_controller.remove_attacker(args)
        return json.dumps({"success": True}), 201


class AggDataForward(Resource):
    """
    Class for exposing web service to enter a data_forward entry into the P4
    aggregate.p4
    """
    def __init__(self, **kwargs):
        self.sdn_controller = kwargs['sdn_controller']
        self.parser = reqparse.RequestParser()
        self.parser.add_argument('device_id', type=str, default=0)
        self.parser.add_argument('dst_mac', type=str)
        self.parser.add_argument('output_port', type=str)

    def post(self):
        logger.info('Attack requested')
        args = self.parser.parse_args()

        logger.info('Attack args - [%s]', args)
        self.sdn_controller.add_agg_data_forward(args)
        return json.dumps({"success": True}), 201

    def delete(self):
        logger.info('Attacker to remove')
        args = self.parser.parse_args()

        logger.info('Attack args - [%s]', args)
        self.sdn_controller.del_agg_data_forward(args)
        return json.dumps({"success": True}), 201


class AggAttack(Resource):
    """
    Class for exposing web service to issue an attack call to aggregate.p4
    """
    def __init__(self, **kwargs):
        self.sdn_controller = kwargs['sdn_controller']
        self.parser = reqparse.RequestParser()
        self.parser.add_argument('src_mac', type=str)
        self.parser.add_argument('dst_ip', type=str)
        self.parser.add_argument('dst_port', type=str)

    def post(self):
        logger.info('Attack requested')
        args = self.parser.parse_args()

        logger.info('Attack args - [%s]', args)
        self.sdn_controller.add_agg_attacker(args)
        return json.dumps({"success": True}), 201

    def delete(self):
        logger.info('Attacker to remove')
        args = self.parser.parse_args()

        logger.info('Attack args - [%s]', args)
        self.sdn_controller.remove_agg_attacker(args)
        return json.dumps({"success": True}), 201


class CoreDataForward(AggDataForward):
    """
    Class for exposing web service to enter a data_forward entry into the P4
    core.p4
    """
    def post(self):
        logger.info('Attack requested')
        args = self.parser.parse_args()

        logger.info('Attack args - [%s]', args)
        self.sdn_controller.add_core_data_forward(args)
        return json.dumps({"success": True}), 201

    def delete(self):
        logger.info('Attacker to remove')
        args = self.parser.parse_args()

        logger.info('Attack args - [%s]', args)
        self.sdn_controller.del_agg_data_forward(args)
        return json.dumps({"success": True}), 201


class Shutdown(Resource):
    @staticmethod
    def post():
        func = request.environ.get('werkzeug.server.shutdown')
        if func is None:
            raise RuntimeError('Not running with the Werkzeug Server')
        func()
