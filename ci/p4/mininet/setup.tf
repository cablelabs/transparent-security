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

# Create and inject own SSH keys for being able to SSH into self or mininet hosts
resource "null_resource" "transparent-security-mininet-setup" {
  provisioner "remote-exec" {
    inline = [
      "ssh-keygen -t rsa -N '' -f ~/.ssh/id_rsa",
      "touch ~/.ssh/authorized_keys",
      "chmod 600 ~/.ssh/authorized_keys",
      "cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys",
    ]
  }
  connection {
    host = aws_instance.transparent-security-mininet-integration.public_ip
    type = "ssh"
    user = var.sudo_user
    private_key = file(var.private_key_file)
  }
}

#Setup transparent-security directory and install dependencies on the remote machine
resource "null_resource" "transparent-security-setup-source" {
  depends_on = [null_resource.transparent-security-mininet-setup]
  provisioner "local-exec" {
    command = <<EOT
${var.ANSIBLE_CMD} -u ${var.sudo_user} \
-i ${aws_instance.transparent-security-mininet-integration.public_ip}, \
${var.SETUP_SOURCE} \
--key-file ${var.private_key_file} \
--extra-vars "\
trans_sec_dir=${var.remote_tps_dir}
"\
EOT
  }
}

resource "null_resource" "transparent-security-topology-gen" {
  depends_on = [null_resource.transparent-security-mininet-setup]
  provisioner "local-exec" {
    command = <<EOT
${var.ANSIBLE_CMD} -u ${var.sudo_user} \
-i ${aws_instance.transparent-security-mininet-integration.public_ip}, \
${var.GENERATE_TOPOLOGY} \
--key-file ${var.private_key_file} \
--extra-vars "\
sdn_ip=${aws_instance.transparent-security-mininet-integration.private_ip}
sdn_port=${var.sdn_port}
ae_ip=${aws_instance.transparent-security-mininet-integration.private_ip}
ae_dev_intf=${var.ae_dev_intf}
sdn_dev_intf=${var.sdn_dev_intf}
trans_sec_dir=${var.src_dir}
topo_file_loc=${var.remote_scripts_dir}/${var.topo_file}
remote_scripts_dir=${var.remote_scripts_dir}
"\
EOT
  }
}

resource "null_resource" "transparent-security-start-mininet" {
  depends_on = [
    null_resource.transparent-security-setup-source,
    null_resource.transparent-security-topology-gen,
  ]
  provisioner "local-exec" {
    command = <<EOT
${var.ANSIBLE_CMD} -u ${var.sudo_user} \
-i ${aws_instance.transparent-security-mininet-integration.public_ip}, \
${var.START_MININET} \
--key-file ${var.private_key_file} \
--extra-vars "\
remote_tps_dir=${var.remote_tps_dir}
service_name=tps-mininet
srvc_desc='Mininet for TPS'
local_srvc_script_tmplt_file=${abspath(var.local_scripts_dir)}/mininet_service.sh.j2
remote_scripts_dir=${var.remote_scripts_dir}
topo_file_loc=${var.remote_scripts_dir}/${var.topo_file}
srvc_log_dir=${var.remote_srvc_log_dir}
srvc_start_pause_time=20
port_to_wait=50051
devices_conf_file=${var.remote_scripts_dir}/${var.dev_daemon_file}
remote_ansible_inventory=${var.remote_inventory_file}
run_daemons=${var.run_daemons}
"\
EOT
  }
}

resource "null_resource" "transparent-security-sim-start-sdn" {
  depends_on = [null_resource.transparent-security-start-mininet]
  provisioner "local-exec" {
    command = <<EOT
${var.ANSIBLE_CMD} -u ${var.sudo_user} \
-i ${aws_instance.transparent-security-mininet-integration.public_ip}, \
${var.START_SERVICE} \
--key-file ${var.private_key_file} \
--extra-vars "\
remote_tps_dir=${var.remote_tps_dir}
remote_scripts_dir=${var.remote_scripts_dir}
service_name=transparent-security-sdn
srvc_desc='SDN'
local_srvc_script_tmplt_file=${abspath(var.local_scripts_dir)}/sdn_mininet.sh.j2
srvc_start_pause_time=15
port_to_wait=${var.sdn_port}
topo_file_loc=${var.remote_scripts_dir}/${var.topo_file}
srvc_log_dir=${var.remote_srvc_log_dir}
log_level=${var.service_log_level}
"\
EOT
  }
}

resource "null_resource" "transparent-security-start-ae" {
  depends_on = [null_resource.transparent-security-sim-start-sdn]
  provisioner "local-exec" {
    command = <<EOT
${var.ANSIBLE_CMD} -u ${var.sudo_user} \
-i ${aws_instance.transparent-security-mininet-integration.public_ip}, \
${var.START_SERVICE} \
--key-file ${var.private_key_file} \
--extra-vars "\
remote_tps_dir=${var.remote_tps_dir}
service_name=transparent-security-ae
srvc_desc='TPS-AE'
srvc_type='SIMPLE'
local_srvc_script_tmplt_file=${abspath(var.local_scripts_dir)}/ae_service.sh.j2
remote_scripts_dir=${var.remote_scripts_dir}
srvc_log_dir=${var.remote_srvc_log_dir}
sdn_url=http://${var.sdn_host}:${var.sdn_port}
log_level=${var.service_log_level}
monitor_intf=${var.ae_monitor_intf}
"\
EOT
  }
}
