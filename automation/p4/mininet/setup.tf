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
resource "null_resource" "transparent-security-host-ssh-setup" {
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

#Create a local inventory to store variables and public IP of remote machine
resource "null_resource" "transparent-security-local-inventory" {
  depends_on = [null_resource.transparent-security-host-ssh-setup]
  provisioner "local-exec" {
    command = <<EOT
${var.ANSIBLE_CMD} \
${var.LOCAL_INVENTORY} \
--extra-vars "\
public_ip=${aws_instance.transparent-security-mininet-integration.public_ip}
local_inventory=${var.local_inventory_file}
"\
EOT
  }
}


#Setup transparent-security directory and install dependencies on the remote machine
resource "null_resource" "transparent-security-mininet-host-setup" {
  depends_on = [null_resource.transparent-security-local-inventory]
  provisioner "local-exec" {
    command = <<EOT
${var.ANSIBLE_CMD} -u ${var.sudo_user} \
-i ${var.local_inventory_file} \
${var.SETUP_MININET_HOST} \
--key-file ${var.private_key_file} \
EOT
  }
}

resource "null_resource" "transparent-security-start-sim" {
  depends_on = [null_resource.transparent-security-mininet-host-setup]

  provisioner "remote-exec" {
    inline = [
      "sudo pip install ansible",
      "${var.ANSIBLE_CMD} -i ${var.remote_var_inventory}  ${var.remote_pb_dir}/mininet/${var.setup_mininet}"
    ]
  }

  connection {
    host = aws_instance.transparent-security-mininet-integration.public_ip
    type     = "ssh"
    user     = var.sudo_user
    private_key = file(var.private_key_file)
  }
}