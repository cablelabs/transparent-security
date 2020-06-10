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

# Optional Variables
variable "public_key_file" {default = "~/.ssh/id_rsa.pub"}
variable "private_key_file" {default = "~/.ssh/id_rsa"}
variable "sudo_user" {default = "ubuntu"}
variable "region" {default = "us-west-2"}

variable "tofino" {
  default = {
    sde_version = "9.2.0"
    ami = "ami-0584c2d36652503c3" // new p4-rt build w/ additions
  }
}

variable "switch_instance_type" {default = "t2.2xlarge"}
variable "orch_instance_type" {default = "t2.medium"}
variable "node_instance_type" {default = "t2.micro"}
variable "num_switches" {default = 5}
variable "num_nodes" {default = 9}

# Variables for ansible playbooks
variable "ANSIBLE_CMD" {default = "export ANSIBLE_HOST_KEY_CHECKING=False; ansible-playbook"}
variable "SETUP_ORCH" {default = "../../../playbooks/tofino/setup_orchestrator.yml"}
variable "START_SERVICE" {default = "../../../playbooks/general/start_service.yml"}

variable "tunnel_intf" {default = "veth1"}
variable "remote_pb_dir" {default = "/home/ubuntu/transparent-security/playbooks"}
variable "remote_inventory_file" {default = "/home/ubuntu/transparent-security.ini"}
variable "remote_tps_dir" {default = "/home/ubuntu/transparent-security"}
variable "remote_scripts_dir" {default = "/etc/transparent-security"}
variable "remote_srvc_log_dir" {default = "/var/log/transparent-security"}
variable "topo_file_loc" {default = "/home/ubuntu/tofino-sim-topology.yaml"}
variable "tofino_model_start_port" {default = "8000"}
variable "tofino_model_end_port" {default = "8004"}
variable "grpc_port" {default = "50051"}
variable "p4_bridge_subnet" {default = "192.168.0.0/24"}
variable "p4_bridge_ip" {default = "192.168.0.1"}
variable "switchd_port" {default = "9999"}
variable "sdn_port" {default = "9998"}
variable "node_nic_name" {default = "eth0"}
variable "switch_nic_prfx" {default = "veth"}
variable "service_log_level" {default = "INFO"}
variable "ae_monitor_intf" {default = "eth0:0"}

variable "setup_nodes_pb" {default = "setup_nodes.yml"}
variable "scenario_name" {default = "all"}
