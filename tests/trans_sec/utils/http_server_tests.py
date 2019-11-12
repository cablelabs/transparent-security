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
# Unit tests for http_session.py
import unittest
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from trans_sec.utils.http_session import HttpSession


class HttpSessionTests(unittest.TestCase):
    """
    Unit tests for utility functions in convert.py
    """

    def setUp(self):
        """
        Start HTTP server
        :return:
        """
        class RequestHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.send_response(200, 'bar')
                self.finish()

        self.http_server = HTTPServer(('', 5555), RequestHandler)
        self.http_server.server_activate()
        address = self.http_server.server_address

        # Class under test trans_sec.utils.http_session.HttpSession
        self.http_session = HttpSession("http://{}:{}".format(
            address[0], address[1]))
        self.assertIsNotNone(self.http_session)

    def tearDown(self):
        """
        Stop HTTP server
        :return:
        """
        # self.http_server.socket.close()
        self.http_server.server_close()

    def test_session(self):
        self.assertTrue(self.http_session.is_authorized())

    # TODO add more unit tests of the class
    #  trans_sec.utils.http_session.HttpSession
    #  note: HTTP server unit tests are much better supported in Python 3.x+
