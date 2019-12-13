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

# Required Variables
variable "access_key" {}
variable "secret_key" {}
variable "build_id" {}
variable "ec2_region" {}
variable "env_type" {}
variable "bf_sde_s3_bucket" {default = "null"}

# Optional Variables
variable "public_key_file" {default = "~/.ssh/id_rsa.pub"}
variable "private_key_file" {default = "~/.ssh/id_rsa"}
variable "sudo_user" {default = "ubuntu"}

# ubuntu 16
variable "base_ami" {default = "ami-08692d171e3cf02d6"}
variable "instance_type" {default = "t2.2xlarge"}
variable "run_tests" {default = "yes"}

# Dependency version only for tofino environments
variable "bf_sde_version" {default = "8.9.2"}

# Dependency versions only for mininet environments
variable "grpc_version" {default = "v1.19.1"}
variable "p4c_version" {default = "fbe395bbf1eed9653323ac73b20cf6c06af2121e"}
variable "protobuf_version" {default = "3.6.x"}
variable "pi_version" {default = "1539ecd8a50c159b011d9c5a9c0eba99f122a845"}
variable "bm_version" {default = "16c699953ee02306731ebf9a9241ea9fe3bbdc8c"}

# Playbook Constants
variable "ANSIBLE_CMD" {default = "export ANSIBLE_HOST_KEY_CHECKING=False; ansible-playbook"}

# File paths are relative to this directory
variable "ANSIBLE_PB_PATH" {default = "../../playbooks"}
