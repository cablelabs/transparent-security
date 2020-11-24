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

locals {
  sdn_ip = aws_instance.orchestrator.private_ip

  # For full & lab_trial scenarios
  core_switch_ip = var.scenario_name == "full" || var.scenario_name == "lab_trial" ? aws_instance.tps-switch.0.private_ip: "n/a"
  core_tun1_ip = var.scenario_name == "full" || var.scenario_name == "lab_trial" ? aws_network_interface.switch_tun_1.0.private_ip: "n/a"
  core_tun1_mac = var.scenario_name == "full" || var.scenario_name == "lab_trial" ? aws_network_interface.switch_tun_1.0.mac_address: "n/a"
  agg_switch_ip = var.scenario_name == "full" || var.scenario_name == "lab_trial" ? aws_instance.tps-switch.1.private_ip: "n/a"
  agg_tun1_ip = var.scenario_name == "full" || var.scenario_name == "lab_trial" ? aws_network_interface.switch_tun_1.1.private_ip: "n/a"
  agg_tun1_mac = var.scenario_name == "full" || var.scenario_name == "lab_trial" ? aws_network_interface.switch_tun_1.1.mac_address: "n/a"

  # For full scenario
  gateway_1_ip = var.scenario_name == "full" ? aws_instance.tps-switch.2.private_ip: "n/a"
  gateway_2_ip = var.scenario_name == "full" ? aws_instance.tps-switch.3.private_ip: "n/a"
  gateway_3_ip = var.scenario_name == "full" ? aws_instance.tps-switch.4.private_ip: "n/a"
  camera_1_ip = var.scenario_name == "full" ? aws_instance.node.0.private_ip: "n/a"
  nas_1_ip = var.scenario_name == "full" ? aws_instance.node.1.private_ip: "n/a"
  game_1_ip = var.scenario_name == "full" ? aws_instance.node.2.private_ip: "n/a"
  camera_2_ip = var.scenario_name == "full" ? aws_instance.node.3.private_ip: "n/a"
  game_2_ip = var.scenario_name == "full" ? aws_instance.node.4.private_ip: "n/a"
  camera_3_ip = var.scenario_name == "full" ? aws_instance.node.5.private_ip: "n/a"
  game_3_ip = var.scenario_name == "full" ? aws_instance.node.6.private_ip: "n/a"

  # For lab_trial scenario
  ae_ip = var.scenario_name == "lab_trial" ? aws_instance.ae.private_ip: "n/a"
  ae_tun1_ip = var.scenario_name == "lab_trial" ? aws_network_interface.ae_tun_1.private_ip: "n/a"
  ae_tun1_mac = var.scenario_name == "lab_trial" ? aws_network_interface.ae_tun_1.mac_address: "n/a"

  # For single-switch scenario
  switch_ip = var.scenario_name == "full" ? "n/a" : aws_instance.tps-switch.0.private_ip
  switch_tun1_ip = var.scenario_name == "full" ? "n/a" : aws_network_interface.switch_tun_1.0.private_ip
  switch_tun1_mac = var.scenario_name == "full" ? "n/a" : aws_network_interface.switch_tun_1.0.mac_address
  clone_ip = var.scenario_name == "full" ? "n/a" : aws_instance.node.2.private_ip
  clone_tun1_ip = var.scenario_name == "full" ? "n/a" : aws_network_interface.node_tun_1.2.private_ip
  clone_tun1_mac = var.scenario_name == "full" ? "n/a" : aws_network_interface.node_tun_1.2.mac_address

  # For single_switch & lab_trial scenarios
  host1_ip = var.scenario_name == "full" ? "n/a" : aws_instance.node.0.private_ip
  host1_tun1_ip = var.scenario_name == "full" ? "n/a" : aws_network_interface.node_tun_1.0.private_ip
  host1_tun1_mac = var.scenario_name == "full" ? "n/a" : aws_network_interface.node_tun_1.0.mac_address
  host2_ip = var.scenario_name == "full" ? "n/a" : aws_instance.node.1.private_ip
  host2_tun1_ip = var.scenario_name == "full" ? "n/a" : aws_network_interface.node_tun_1.1.private_ip
  host2_tun1_mac = var.scenario_name == "full" ? "n/a" : aws_network_interface.node_tun_1.1.mac_address

  # For lab_trial scenarios
  lab_inet_ip = var.scenario_name == "lab_trial" ? aws_instance.node.2.private_ip: "n/a"
  lab_inet_tun1_ip = var.scenario_name == "lab_trial" ? aws_network_interface.node_tun_1.2.private_ip: "n/a"
  lab_inet_tun1_mac = var.scenario_name == "lab_trial" ? aws_network_interface.node_tun_1.2.mac_address: "n/a"

  p4_arch = var.scenario_name == "core" ? "tna" : "v1model"
  grpc_port = var.p4_arch == "tna" ? var.bf_grpc_port : var.p4_grpc_port
}

########
# Setup
########

# Call ensure SSH key has correct permissions
resource "null_resource" "tps-tofino-sim-setup" {
  provisioner "local-exec" {
    command = "chmod 600 ${var.private_key_file}"
  }
}

// Setup private key on the orchestrator so it can have ssh access into the switch and node VMs
resource "null_resource" "tps-tofino-orch-key-setup" {
  depends_on = [
    aws_instance.orchestrator,
    null_resource.tps-tofino-sim-setup,
    aws_network_interface.node_tun_1,
    aws_network_interface.switch_tun_1,
  ]
  provisioner "local-exec" {
    command = <<EOT
scp -o StrictHostKeyChecking=no ${var.private_key_file} ${var.orch_user}@${aws_instance.orchestrator.public_ip}:~/.ssh/id_rsa"
ssh -o StrictHostKeyChecking=no ${var.orch_user}@${aws_instance.orchestrator.public_ip} 'chmod 600 ~/.ssh/id_rsa'"
EOT
  }
}

resource "null_resource" "tps-sim-setup-orch-single-switch" {
  count = var.scenario_name == "full" || var.scenario_name == "lab_trial" ? 0 : 1
  depends_on = [
    aws_instance.tps-switch,
    aws_instance.node,
    null_resource.tps-tofino-orch-key-setup,
  ]
  provisioner "local-exec" {
    command = <<EOT
${var.ANSIBLE_CMD} -u ${var.orch_user} \
-i ${aws_instance.orchestrator.public_ip}, \
${var.SETUP_ORCH_SINGLE_SWITCH} \
--key-file ${var.private_key_file} \
--extra-vars "\
scenario_name=${var.scenario_name}
host_user=${var.node_user}
host1_ip=${local.host1_ip}
host1_tun1_ip=${local.host1_tun1_ip}
host1_tun1_mac=${local.host1_tun1_mac}
host2_ip=${local.host2_ip}
host2_tun1_ip=${local.host2_tun1_ip}
host2_tun1_mac=${local.host2_tun1_mac}
clone_ip=${local.clone_ip}
ae_ip=${local.clone_ip}
clone_tun1_ip=${local.clone_tun1_ip}
clone_tun1_mac=${local.clone_tun1_mac}
switch_user=${var.switch_user}
switch_ip=${local.switch_ip}
switch_tun1_ip=${local.switch_tun1_ip}
switch_tun1_mac=${local.switch_tun1_mac}
topo_file_loc=${var.topo_file_loc}
sde_dir=/home/${var.orch_user}/bf-sde-${var.tofino.sde_version}
log_dir=${var.remote_srvc_log_dir}
remote_scripts_dir=${var.remote_scripts_dir}
tofino_model_port=${var.tofino_model_start_port}
grpc_port=${local.grpc_port}
sdn_ip=${aws_instance.orchestrator.private_ip}
sdn_port=${var.sdn_port}
remote_ansible_inventory=${var.remote_inventory_file}
ae_monitor_intf=${var.ae_monitor_intf}
clone_egress_port=${var.clone_egress_port}
p4_arch=${var.p4_arch}
"\
EOT
  }
}


resource "null_resource" "tps-sim-setup-orch-lab-trial" {
  count = var.scenario_name == "lab_trial" ? 1 : 0
  depends_on = [
    aws_instance.tps-switch,
    aws_instance.node,
    null_resource.tps-tofino-orch-key-setup,
  ]
  provisioner "local-exec" {
    command = <<EOT
${var.ANSIBLE_CMD} -u ${var.orch_user} \
-i ${aws_instance.orchestrator.public_ip}, \
${var.SETUP_ORCH_LAB_TRIAL} \
--key-file ${var.private_key_file} \
--extra-vars "\
scenario_name=${var.scenario_name}
host_user=${var.node_user}
host1_ip=${local.host1_ip}
host1_tun1_ip=${local.host1_tun1_ip}
host1_tun1_mac=${local.host1_tun1_mac}
host2_ip=${local.host2_ip}
host2_tun1_ip=${local.host2_tun1_ip}
host2_tun1_mac=${local.host2_tun1_mac}
inet_ip=${local.lab_inet_ip}
inet_tun1_ip=${local.lab_inet_tun1_ip}
inet_tun1_mac=${local.lab_inet_tun1_mac}
ae_user=${var.ae_user}
ae_ip=${local.ae_ip}
ae_tun1_ip=${local.ae_tun1_ip}
ae_tun1_mac=${local.ae_tun1_mac}
switch_user=${var.switch_user}
agg_ip=${local.agg_switch_ip}
agg_tun1_ip=${local.agg_tun1_ip}
agg_tun1_mac=${local.agg_tun1_mac}
core_ip=${local.core_switch_ip}
core_tun1_ip=${local.core_tun1_ip}
core_tun1_mac=${local.core_tun1_mac}
topo_file_loc=${var.topo_file_loc}
sde_dir=/home/${var.orch_user}/bf-sde-${var.tofino.sde_version}
log_dir=${var.remote_srvc_log_dir}
remote_scripts_dir=${var.remote_scripts_dir}
tofino_model_port=${var.tofino_model_start_port}
grpc_port=${local.grpc_port}
sdn_ip=${aws_instance.orchestrator.private_ip}
sdn_port=${var.sdn_port}
remote_ansible_inventory=${var.remote_inventory_file}
ae_monitor_intf=${var.ae_lab_intf}
clone_egress_port=${var.clone_egress_port}
p4_arch=${var.p4_arch}
"\
EOT
  }
}

locals {
  setup_pb = var.scenario_name == "full" || var.scenario_name == "lab_trial" ? "setup_nodes-${var.scenario_name}.yml" : "setup_nodes-single_switch.yml"
}

resource "null_resource" "tps-tofino-setup-nodes" {
  depends_on = [
    null_resource.tps-sim-setup-orch-single-switch,
    null_resource.tps-sim-setup-orch-lab-trial
  ]

  provisioner "remote-exec" {
    inline = [
      "sudo pip install ansible",
      "${var.ANSIBLE_CMD} -i ${var.remote_inventory_file} ${var.remote_pb_dir}/tofino/${local.setup_pb} --extra-vars='scenario_name=${var.scenario_name}'"
    ]
  }

  connection {
    host = aws_instance.orchestrator.public_ip
    type     = "ssh"
    user     = var.orch_user
    private_key = file(var.private_key_file)
  }
}
