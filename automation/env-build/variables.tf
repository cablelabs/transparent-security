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
variable "env_type" {default = "mininet"}

# Dependency version only for tofino environments
variable "bf_sde_s3_bucket" {default = "null"}

# Optional Variables
variable "bf_sde_version" {default = "9.2.0"}
variable "bf_sde_profile" {default = "p4_runtime_profile"}
variable "create_ami" {default = "yes"}
variable "public_key_file" {default = "~/.ssh/id_rsa.pub"}
variable "private_key_file" {default = "~/.ssh/id_rsa"}
variable "sudo_user" {default = "ubuntu"}
variable "ubuntu_version" {default = "18"}
variable "python_version" {default = "3.6"}

# snaps-hcp image
variable "centos7_ami" {default="ami-01ed306a12b7d1c96"}

# ubuntu 16
variable "base_16_ami" {default = "ami-08692d171e3cf02d6"}
# ubuntu 18
variable "base_18_ami" {default = "ami-06f2f779464715dc5"}
# ubuntu 20 (Siddhi AE image)
variable "base_20_ami" {default = "ami-03d5c68bab01f3496"}

variable "instance_type" {default = "t2.2xlarge"}
variable "run_tests" {default = "yes"}

# Dependency versions only for mininet environments
variable "grpc_version" {default = "v1.19.1"}
variable "p4c_version" {default = "fbe395bbf1eed9653323ac73b20cf6c06af2121e"}
variable "protobuf_version" {default = "3.6.x"}
variable "pi_version" {default = "1539ecd8a50c159b011d9c5a9c0eba99f122a845"}
variable "bm_version" {default = "16c699953ee02306731ebf9a9241ea9fe3bbdc8c"}
variable "remote_scripts_dir" {default = "/etc/transparent-security"}

# Playbook Constants
variable "ANSIBLE_CMD" {default = "export ANSIBLE_HOST_KEY_CHECKING=False; ansible-playbook"}

# File paths are relative to this directory
variable "ANSIBLE_PB_PATH" {default = "../../playbooks"}
