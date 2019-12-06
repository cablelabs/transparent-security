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


class Error(Exception):
    """Base class for drb-exceptions in this module."""

    def __init__(self, expression, message, status, body):
        self.expression = expression
        self.message = message
        self.status = status
        self.body = body

    def __str__(self):
        return 'Status: ' + str(
            self.status) + ' ' + self.message + '\n' + self.body


class AuthorizationError(Error):
    """Exception raised for authorization errors.
    Attributes:
        expression -- input expression in which the error occurred
        message -- explanation of the error
    """

    def __init__(self, expression, message, status, body):
        Error.__init__(self, expression, message, status, body)


class ConnectionError(Error):
    """Exception raised for connection errors.
    Attributes:
        expression -- url in which the error occurred
        message -- explanation of the error
    """

    def __init__(self, expression, message, status, body):
        Error.__init__(self, expression, message, status, body)


class TSError(Exception):
    """Base class for pdp-exceptions in this module."""

    def __init__(self, expression, message):
        self.expression = expression
        self.message = message

    def __str__(self):
        return 'Error on ' + self.expression + ':  ' + self.message


class ActionError(TSError):
    """Exception raised for authorization errors.
    Attributes:
        expression -- input expression in which the error occurred
        message -- explanation of the error
    """

    def __init__(self, action, message):
        TSError.__init__(self, action, message)


class AlreadyExistsError(TSError):
    """Exception raised trying to create an existing resource.
       Attributes:
        expression -- input expression in which the error occurred
        message -- explanation of the error
    """
    def __init__(self, key, message):
        TSError.__init__(self, key, message)


class NotFoundError(TSError):
    """Exception raised when a resource doesn't exist errors.
    Attributes:
        expression -- input expression in which the error occurred
        message -- explanation of the error
    """
    def __init__(self, key, message):
        TSError.__init__(self, key, message)
