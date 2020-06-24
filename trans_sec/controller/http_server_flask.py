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
    def __init__(self, sdn_controller, port=9998):
        self.sdn_controller = sdn_controller
        self.port = port
        self.thread = threading.Thread(target=self.flask_thread, args=(port,))
        self.api = Api(http_server)
        self.server_start = None

    def start(self):
        self.thread.start()
        self.api.add_resource(
            Attack, '/attack',
            resource_class_kwargs={'sdn_controller': self.sdn_controller})
        self.api.add_resource(Shutdown, '/shutdown')

    @staticmethod
    def stop():
        try:
            requests.post(url='http://127.0.0.1:9998/shutdown')
        except Exception as e:
            logger.warning('Trouble shutting down HTTP server - [%s]', e)

    def flask_thread(self, port):
        logger.info('Starting server on port [%s]', port)
        self.server_start = http_server.run(port=port)


class Attack(Resource):
    def __init__(self, **kwargs):
        self.sdn_controller = kwargs['sdn_controller']

    def post(self):
        logger.info('Attack requested')
        parser = reqparse.RequestParser()
        parser.add_argument('src_mac', type=str)
        parser.add_argument('src_ip', type=str)
        parser.add_argument('dst_ip', type=str)
        parser.add_argument('dst_port', type=str)
        parser.add_argument('packet_size', type=str)
        parser.add_argument('attack_type', type=str)
        args = parser.parse_args()

        logger.info('Attack args - [%s]', args)
        self.sdn_controller.add_attacker(args)
        return json.dumps({"success": True}), 201


class Shutdown(Resource):
    @staticmethod
    def post():
        func = request.environ.get('werkzeug.server.shutdown')
        if func is None:
            raise RuntimeError('Not running with the Werkzeug Server')
        func()
