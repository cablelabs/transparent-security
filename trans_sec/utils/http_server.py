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
# noinspection PyCompatibility
import json
import logging
# noinspection PyCompatibility
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
# noinspection PyCompatibility
from SocketServer import ThreadingMixIn

logger = logging.getLogger('http_server')


class Handler(object, BaseHTTPRequestHandler):
    def __init__(self, sdn_controller=None):
        super(self.__class__, self).__init__()
        self.sdn_controller = sdn_controller

    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_GET(self):
        logger.debug('Returning attack value [%s]', self.sdn_controller.attack)
        self.send_response(200)
        self.end_headers()
        if self.sdn_controller:
            self.wfile.write(self.sdn_controller.attack)
        else:
            message = {'active': False}
            self.wfile.write(json.dumps(message))

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)
        body = json.loads(body)
        logger.debug('Sending message body [%s]', body)

        message = {'msg': 'ok'}
        self._set_headers()
        self.wfile.write(json.dumps(message))
        if self.sdn_controller:
            self.sdn_controller.add_attacker(body)


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Handle requests in a separate thread."""
