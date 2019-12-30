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
resource "aws_instance" "transparent-security-build-img" {
  ami = var.base_ami
  instance_type = var.instance_type
  key_name = aws_key_pair.transparent-security-mini-pk.key_name

  tags = {
    Name = "transparent-security-env-build-${var.build_id}"
  }

  security_groups = [aws_security_group.transparent-security-img-sg.name]
  associate_public_ip_address = true

  # Used to ensure host is really up before attempting to apply ansible playbooks
  provisioner "remote-exec" {
    inline = [
      "sudo apt-get update",
      "sudo apt-get install python2.7 -y",
      "sudo ln /usr/bin/python2.7 /usr/bin/python"
    ]

    # Remote connection info for remote-exec
    connection {
      host = self.public_ip
      type     = "ssh"
      user     = var.sudo_user
      private_key = file(var.private_key_file)
    }
  }

  root_block_device {
    volume_size = "50"
  }
}

# Setup environment
resource "null_resource" "env_provision" {
  depends_on = [aws_instance.transparent-security-build-img]

  provisioner "local-exec" {
    command = <<EOT
${var.ANSIBLE_CMD} -u ${var.sudo_user} \
-i ${aws_instance.transparent-security-build-img.public_ip}, \
-u ${var.sudo_user} \
${var.ANSIBLE_PB_PATH}/${var.env_type}/env_build.yml \
--key-file ${var.private_key_file} \
--extra-vars "\
aws_access_key=${var.access_key}
aws_secret_key=${var.secret_key}
grpc_version=${var.grpc_version}
p4c_version=${var.p4c_version}
protobuf_version=${var.protobuf_version}
pi_version=${var.pi_version}
bm_version=${var.bm_version}
bf_sde_version=${var.bf_sde_version}
bf_sde_s3_bucket=${var.bf_sde_s3_bucket}
"\
EOT
  }
}

resource "aws_ami_from_instance" "transparent-security-env-build" {
  depends_on = [null_resource.env_provision]
  count = var.create_ami == "yes" ? 1 : 0
  name               = "transparent-security-env-build-${var.build_id}"
  source_instance_id = aws_instance.transparent-security-build-img.id
}
