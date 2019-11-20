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
variable "ec2_region" {default = "us-west-2"}

# Optional Variables
variable "public_key_file" {default = "~/.ssh/id_rsa.pub"}
variable "private_key_file" {default = "~/.ssh/id_rsa"}
variable "sudo_user" {default = "ubuntu"}

# ubuntu 16
variable "base_ami" {default = "ami-08692d171e3cf02d6"}
variable "instance_type" {default = "t2.2xlarge"}
variable "run_tests" {default = "yes"}

# Consider upgrading the GRPC version, current stable is v1.24.3
variable "grpc_version" {default = "v1.3.2"}
variable "p4c_version" {default = "69e132d0d663e3408d740aaf8ed534ecefc88810"}
# Consider upgrading the protobuf version, current stable is 3.10.x
variable "protobuf_version" {default = "3.2.x"}
variable "pi_version" {default = "41358da0ff32c94fa13179b9cee0ab597c9ccbcc"}
variable "bm_version" {default = "b447ac4c0cfd83e5e72a3cc6120251c1e91128ab"}

# Playbook Constants
variable "ANSIBLE_CMD" {default = "export ANSIBLE_HOST_KEY_CHECKING=False; ansible-playbook"}

# File paths are relative to this directory
variable "ANSIBLE_PB_PATH" {default = "../../playbooks"}
