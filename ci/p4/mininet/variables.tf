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
variable "mininet_ami" {default ="ami-060d055b5ca40de8c"}

# Optional Variables
variable "public_key_file" {default = "~/.ssh/id_rsa.pub"}
variable "private_key_file" {default = "~/.ssh/id_rsa"}
variable "sudo_user" {default = "ubuntu"}
variable "instance_type" {default = "t2.2xlarge"}

# Playbook Constants
variable "ANSIBLE_CMD" {default = "export ANSIBLE_HOST_KEY_CHECKING=False; ansible-playbook"}

# File paths are relative to this directory
variable "ANSIBLE_PB_PATH" {default = "../../../playbooks"}
variable "src_dir" {default = "~/transparent-security"}
variable "remote_scripts_dir" {default = "/etc/transparent-security"}
variable "remote_pb_dir" {default = "/home/ubuntu/transparent-security/playbooks"}
variable "remote_var_inventory" {default = "/home/ubuntu/variables.ini"}
variable "remote_inventory_file" {default = "/home/ubuntu/transparent-security.ini"}
variable "run_daemons" {default = "True"}
variable "topo_file" {default = "mininet-sim-topology.yaml"}
variable "dev_daemon_file" {default = "device-daemons.yml"}
variable "local_scripts_dir" {default = "../../../playbooks/general/templates"}
variable "clone_egress_port" {default = "3"}
variable "sdn_host" {default = "localhost"}
variable "dashboard_port" {default = "8080"}
variable "sdn_port" {default = "9998"}
variable "sdn_dev_intf" {default = "lo"} # TODO - verify if this is correct???
variable "ae_dev_intf" {default = "lo"} # TODO - verify if this is correct???
variable "ae_monitor_intf" {default = "core1-eth3"}
variable "service_log_level" {default = "INFO"}
variable "remote_srvc_log_dir" {default = "/var/log/transparent-security"}
variable "remote_tps_dir" {default = "/home/ubuntu/transparent-security"}

# Variables for ansible playbooks
variable "SETUP_SOURCE" {default = "../../../playbooks/general/setup_source.yml"}
variable "START_MININET" {default = "../../../playbooks/mininet/start_mininet.yml"}
variable "GENERATE_TOPOLOGY" {default = "../../../playbooks/mininet/generate_topology.yml"}
variable "START_SERVICE" {default = "../../../playbooks/general/start_service.yml"}
variable "SCENARIOS_DIR" {default = "../../../playbooks/scenarios"}
variable "remote_scenario_pb_dir" {default = "/home/ubuntu/transparent-security/playbooks/scenarios"}
variable "scenario_name" {default = "simple"}
variable "setup_mininet" {default = "setup_mininet.yml"}
