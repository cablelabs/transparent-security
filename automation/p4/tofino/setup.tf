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
  core_switch_ip = aws_instance.tps-switch.0.private_ip
  agg_switch_ip = aws_instance.tps-switch.1.private_ip
  gateway_1_ip = aws_instance.tps-switch.2.private_ip
  gateway_2_ip = aws_instance.tps-switch.3.private_ip
  gateway_3_ip = aws_instance.tps-switch.4.private_ip
  camera_1_ip = aws_instance.node.0.private_ip
  nas_1_ip = aws_instance.node.1.private_ip
  game_1_ip = aws_instance.node.2.private_ip
  camera_2_ip = aws_instance.node.3.private_ip
  game_2_ip = aws_instance.node.4.private_ip
  camera_3_ip = aws_instance.node.5.private_ip
  game_3_ip = aws_instance.node.6.private_ip
  inet_ip = aws_instance.node.7.private_ip
  ae_ip = aws_instance.node.8.private_ip
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
  depends_on = [aws_instance.orchestrator, null_resource.tps-tofino-sim-setup]
  provisioner "local-exec" {
    command = <<EOT
scp -o StrictHostKeyChecking=no ${var.private_key_file} ${var.sudo_user}@${aws_instance.orchestrator.public_ip}:~/.ssh/id_rsa"
ssh -o StrictHostKeyChecking=no ${var.sudo_user}@${aws_instance.orchestrator.public_ip} 'chmod 600 ~/.ssh/id_rsa'"
EOT
  }
}

resource "null_resource" "tps-sim-setup-orch" {
  depends_on = [
    aws_instance.tps-switch,
    aws_instance.node,
    null_resource.tps-tofino-orch-key-setup,
  ]
  provisioner "local-exec" {
    command = <<EOT
${var.ANSIBLE_CMD} -u ${var.sudo_user} \
-i ${aws_instance.orchestrator.public_ip}, \
${var.SETUP_ORCH} \
--key-file ${var.private_key_file} \
--extra-vars "\
core_ip=${local.core_switch_ip}
agg_ip=${local.agg_switch_ip}
gateway1_ip=${local.gateway_1_ip}
gateway2_ip=${local.gateway_2_ip}
gateway3_ip=${local.gateway_3_ip}
sdn_ip=${local.sdn_ip}
camera1_ip=${local.camera_1_ip}
nas1_ip=${local.nas_1_ip}
game1_ip=${local.game_1_ip}
camera2_ip=${local.camera_2_ip}
game2_ip=${local.game_2_ip}
camera3_ip=${local.camera_3_ip}
game3_ip=${local.game_3_ip}
inet_ip=${local.inet_ip}
ae_ip=${local.ae_ip}
topo_file_loc=${var.topo_file_loc}
sde_version=${var.tofino.sde_version}
sde_dir=/home/${var.sudo_user}/bf-sde-${var.tofino.sde_version}
remote_scripts_dir=${var.remote_scripts_dir}
switchd_port=${var.switchd_port}
sdn_port=${var.sdn_port}
tofino_model_port=${var.tofino_model_start_port}
switchd_port=${var.switchd_port}
grpc_port=${var.grpc_port}
sdn_ip=${aws_instance.orchestrator.private_ip}
trans_sec_dir=${var.remote_tps_dir}
remote_ansible_inventory=${var.remote_inventory_file}
node_nic=${var.node_nic_name}
switch_nic_prfx=${var.switch_nic_prfx}
srvc_log_dir=${var.remote_srvc_log_dir}
srvc_log_level=${var.service_log_level}
switch_sudo_user=${var.sudo_user}
host_sudo_user=${var.sudo_user}
ae_monitor_intf=${var.ae_monitor_intf}
p4_platform=tofino
"\
EOT
  }
}

resource "null_resource" "tps-tofino-setup-nodes" {
  depends_on = [null_resource.tps-sim-setup-orch]

  provisioner "remote-exec" {
    inline = [
      "sudo pip install ansible",
      "${var.ANSIBLE_CMD} -i ${var.remote_inventory_file} ${var.remote_pb_dir}/tofino/${var.setup_nodes_pb}"
    ]
  }

  connection {
    host = aws_instance.orchestrator.public_ip
    type     = "ssh"
    user     = var.sudo_user
    private_key = file(var.private_key_file)
  }
}
