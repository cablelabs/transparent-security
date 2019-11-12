# Copyright 2018 Cable Television Laboratories, Inc.
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
import logging

import requests
import urllib3

from trans_sec.exceptions import NotFoundError, AlreadyExistsError

urllib3.disable_warnings()
logger = logging.getLogger('http_session')


class HttpSession:
    def __init__(self, url, username=None, password=None, verify_cert=False):
        self.username = username
        self.password = password
        self.url = url
        self.token = ''
        self.verify_cert = verify_cert
        self.authorized = True

    def authorize(self):
        self.authorized = True

    def is_authorized(self):
        return self.authorized

    def get(self, resource, key=None):
        logger.info('GET resource [%s] with key [%s]', resource, key)
        if not self.is_authorized():
            self.authorize()
        headers = {'Authorization': 'Bearer ' + self.token}
        actual_resource = resource
        if key is not None:
            actual_resource = actual_resource + '/' + key
        r = requests.get(self.url + '/' + actual_resource,
                         headers=headers, verify=False)
        if r.status_code == 200:
            logger.info('GET return value - [%s]', r.json())
            return r.json()
        else:
            logger.error('Error on Get with code and payload [%s]',
                         r.status_code, r.json())
            temp = r.json()
            raise NotFoundError(key, str(temp['Messages'][0]))

    def post(self, resource, body):
        logger.info('POST resource [%s] with body [%s]', resource, body)
        if not self.is_authorized():
            self.authorize()
        headers = {'Authorization': 'Bearer ' + self.token}
        actual_resource = resource
        logger.debug('Post received from %s/%s with body value[\n%s\n]',
                     self.url, actual_resource, body)
        r = requests.post(self.url + '/' + actual_resource,
                          headers=headers, json=body, verify=False)
        if r.status_code == 201 or r.status_code == 200:
            logger.info('POST return value - [%s]', r.json())
            return r.json()
        else:
            logger.error('Error on Post [%s] to URL [%s/%s]',
                         str(r.status_code),
                         self.url, actual_resource)
            temp = r.json()
            if body.get('Name') is not None:
                raise AlreadyExistsError(body['Name'],
                                         str(temp['Messages'][0]))
            else:
                raise AlreadyExistsError(body['Addr'],
                                         str(temp['Messages'][0]))

    def delete(self, resource, key):
        logger.info('DELETE resource [%s] with key [%s]', resource, key)
        if not self.is_authorized():
            self.authorize()
        headers = {'Authorization': 'Bearer ' + self.token}
        actual_resource = resource + '/' + key
        r = requests.delete(self.url + '/' + actual_resource,
                            headers=headers, verify=False)
        if r.status_code == 200:
            logger.info('DELETE return value - [%s]', r.json())
            return r.json()
        elif r.status_code == 404:
            logger.info('Deleting a non-existent object, ignoring')
            return {}
        else:
            logger.error('Error on Delete with code %s and payload [%s]',
                         r.status_code, r.json)
            return r.status_code

    def put(self, resource, body, key):
        logger.info('PUT resource [%s] with key [%s]', resource, key)
        if not self.is_authorized():
            self.authorize()
        headers = {'Authorization': 'Bearer ' + self.token}
        actual_resource = resource + '/' + key
        r = requests.put(self.url + '/' + actual_resource,
                         headers=headers, json=body, verify=False)
        if r.status_code == 200:
            logger.info('PUT return value - [%s]', r.json())
            return r.json()
        else:
            logger.error('Error on Put with code %s and payload [%s]',
                         r.status_code, r.json())
            return r.status_code
