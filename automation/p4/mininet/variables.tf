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
# Image generated from env-build script for build_env='mininet'
variable "mininet_ami" {default ="ami-0ffbdcb5556c35e01"}

# Optional Variables
variable "public_key_file" {default = "~/.ssh/id_rsa.pub"}
variable "private_key_file" {default = "~/.ssh/id_rsa"}
variable "sudo_user" {default = "ubuntu"}
variable "instance_type" {default = "t2.2xlarge"}

# Playbook Constants
variable "ANSIBLE_CMD" {default = "export ANSIBLE_HOST_KEY_CHECKING=False; ansible-playbook"}

# File paths are relative to this directory
variable "remote_scripts_dir" {default = "/etc/transparent-security"}
variable "remote_pb_dir" {default = "/home/ubuntu/transparent-security/playbooks"}
variable "remote_inventory_file" {default = "/home/ubuntu/transparent-security.ini"}
variable "topo_file" {default = "mininet-sim-topology.yaml"}
variable "forwarding_daemon_file" {default = "forwarding-daemons.yml"}
variable "clone_egress_port" {default = "3"}
variable "sdn_host" {default = "localhost"}
variable "ae_host" {default = "localhost"}
variable "sdn_port" {default = "9998"}
variable "sdn_dev_intf" {default = "lo"} # TODO - verify if this is correct???
variable "ae_dev_intf" {default = "lo"} # TODO - verify if this is correct???
variable "ae_monitor_intf" {default = "core-eth3"}
variable "service_log_level" {default = "DEBUG"}
variable "remote_srvc_log_dir" {default = "/var/log/transparent-security"}
variable "host_log_dir" {default = "/home/ubuntu/tps-logs"}
variable "remote_tps_dir" {default = "/home/ubuntu/transparent-security"}

# Variables for ansible playbooks
variable "LOCAL_INVENTORY" {default = "../../../playbooks/mininet/local_inventory.yml"}
variable "SETUP_MININET_HOST" {default = "../../../playbooks/mininet/setup_host.yml"}
variable "remote_scenario_pb_dir" {default = "/home/ubuntu/transparent-security/playbooks/scenarios"}

# Scenario variables
# Also supports "gateway", "aggregate", and "core"
variable "scenario_name" {default = "full"}

# Any other value will run the tests in local mode
variable "test_run_mode" {default = "remote"}

# Default test case that will execute the playbook located at ../../../playbooks/scenarios/<scenario_name>-<test_case>.yml
variable "test_case" {default = "all"}
