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
variable "vpc_id" {default = "vpc-fd820f9b"}
variable "vpc_subnet_prfx" {default = "172.31"}

# Optional Variables
variable "public_key_file" {default = "~/.ssh/id_rsa.pub"}
variable "private_key_file" {default = "~/.ssh/id_rsa"}
variable "orch_user" {default = "ubuntu"}
variable "switch_user" {default = "ubuntu"}
variable "node_user" {default = "ubuntu"}
variable "ae_user" {default = "centos"}
variable "region" {default = "us-west-2"}
variable "availability_zone" {default = "us-west-2a"}

variable "tofino" {
  default = {
    sde_version = "9.2.0"
    p4rt_ami = "ami-043e6714f3d0863f2"
    bfrt_ami = "ami-01a5ff54de23b6739"
  }
}
variable "hcp_ami" {default ="ami-07c9ba265e178c9a3"}

variable "switch_instance_type" {default = "t2.2xlarge"}
variable "ae_instance_type" {default = "t2.large"}
variable "orch_instance_type" {default = "t2.2xlarge"}
variable "node_instance_type" {default = "t2.small"}
variable "num_switches_full" {default = 5}
variable "num_switches_single" {default = 1}
variable "num_switches_lab_trial" {default = 2}
variable "num_nodes_full" {default = 9}
variable "num_nodes_single" {default = 3}
variable "num_nodes_lab_trial" {default = 3}

# Variables for ansible playbooks
variable "ANSIBLE_CMD" {default = "export ANSIBLE_HOST_KEY_CHECKING=False; ansible-playbook"}
variable "SETUP_ORCH_FULL" {default = "../../../playbooks/tofino/setup_orchestrator-full.yml"}
variable "SETUP_ORCH_SINGLE_SWITCH" {default = "../../../playbooks/tofino/setup_orchestrator-single_switch.yml"}
variable "SETUP_ORCH_LAB_TRIAL" {default = "../../../playbooks/tofino/setup_orchestrator-lab_trial.yml"}
variable "START_SERVICE" {default = "../../../playbooks/general/start_service.yml"}
variable "remote_scenario_pb_dir" {default = "/home/ubuntu/transparent-security/playbooks/scenarios"}

variable "tunnel_intf" {default = "veth1"}
variable "remote_pb_dir" {default = "/home/ubuntu/transparent-security/playbooks"}
variable "remote_inventory_file" {default = "/home/ubuntu/transparent-security.yaml"}
variable "remote_tps_dir" {default = "/home/ubuntu/transparent-security"}
variable "remote_scripts_dir" {default = "/etc/transparent-security"}
variable "remote_srvc_log_dir" {default = "/var/log/transparent-security"}
variable "topo_file_loc" {default = "/etc/transparent-security/tofino-sim-topology.yaml"}
variable "tofino_model_start_port" {default = "8000"}
variable "tofino_model_end_port" {default = "8004"}
variable "p4_grpc_port" {default = "50051"}
variable "bf_grpc_port" {default = "50052"}
variable "p4_bridge_subnet" {default = "192.168.0.0/24"}
variable "sdn_port" {default = "9998"}
variable "switch_nic_prfx" {default = "veth"}
variable "service_log_level" {default = "DEBUG"}
variable "ae_monitor_intf" {default = "core-tun"}
variable "ae_lab_intf" {default = "core-tun1"}
variable "clone_egress_port" {default = "3"}
variable "p4_arch" {default = "v1model"}

variable "setup_nodes_pb" {default = "setup_nodes.yml"}
variable "scenario_name" {default = "full"}
variable "test_case" {default = "all"}
