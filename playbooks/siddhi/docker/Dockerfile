# Copyright (c) 2021 Cable Television Laboratories, Inc.
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

FROM siddhiio/siddhi-runner-alpine:5.1.2

RUN apk --update add net-tools tcpdump sudo
RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*
#RUN set -ex && apk --no-cache add sudo

#SHELL ["/bin/bash", "-o", "pipefail", "-c"]
#RUN addgroup siddhi_user sudo
RUN echo 'siddhi_user:siddhi_user' | chpasswd
RUN echo '%wheel ALL=(ALL) ALL' > /etc/sudoers.d/wheel
RUN adduser siddhi_user wheel

ARG classpath_lib=.
COPY $classpath_lib/lib/* /home/siddhi_user/siddhi-runner/lib/
