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

# AWS EC2 Instance
resource "aws_instance" "transparent-security-mininet-integration" {
  ami = var.mininet_ami
  instance_type = var.instance_type
  key_name = aws_key_pair.transparent-security-pk.key_name

  tags = {
    Name = "transparent-security-transparent-security-${var.scenario_name}-${var.build_id}"
  }

  security_groups = [aws_security_group.transparent-security-img-sg.name]
  associate_public_ip_address = true

  # Used to ensure host is really up before attempting to apply ansible playbooks
  provisioner "remote-exec" {
    inline = [
      "sudo echo 'transparent-security mininet integration CI' > ~/motd",
    ]
  }

  # Remote connection info for remote-exec
  connection {
    host = self.public_ip
    type     = "ssh"
    user     = var.sudo_user
    private_key = file(var.private_key_file)
  }

  root_block_device {
    volume_size = "50"
  }
}

resource "aws_instance" "transparent-security-hcp-instance" {
  count = var.scenario_name == "lab_trial" ? 1 : 0
  ami = var.hcp_ami
  instance_type = var.instance_type
  key_name = aws_key_pair.transparent-security-pk.key_name

  tags = {
    Name = "transparent-security-hcp-${var.scenario_name}-${var.build_id}"
  }

  security_groups = [aws_security_group.transparent-security-img-sg.name, aws_security_group.transparent-security-hcp-img-sg.name ]
  associate_public_ip_address = true

  # Used to ensure host is really up before attempting to apply ansible playbooks
  provisioner "remote-exec" {
    inline = [
      "sudo echo 'transparent-security-hcp integration' > ~/motd",
    ]
  }

  # Remote connection info for remote-exec
  connection {
    host = self.public_ip
    type     = "ssh"
    user     = var.hcp_sudo_user
    private_key = file(var.private_key_file)
  }

//  root_block_device {
//    volume_size = "50"
//  }
}
