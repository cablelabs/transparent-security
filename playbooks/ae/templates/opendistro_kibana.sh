# Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# or in the "license" file accompanying this file. This file is distributed
# on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.
# Description:
# Default Kibana configuration for Open Distro.

server.port:  5601
server.host: 0.0.0.0
elasticsearch.hosts: http://localhost:9200
elasticsearch.ssl.verificationMode: none
#elasticsearch.username: admin
#elasticsearch.password: admin
#elasticsearch.requestHeadersWhitelist: ["securitytenant","Authorization"]
#opendistro_security.multitenancy.enabled: true
#opendistro_security.multitenancy.tenants.preferred: ["Private", "Global"]
#opendistro_security.readonly_mode.roles: ["kibana_read_only"]
# Use this setting if you are running kibana without https
#opendistro_security.cookie.secure: false
newsfeed.enabled: false
telemetry.optIn: false
telemetry.enabled: false

