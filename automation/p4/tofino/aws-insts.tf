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

# Orchestrator/SDN Controller Instance
resource "aws_instance" "orchestrator" {
  ami = var.tofino.ami
  instance_type = var.orch_instance_type
  key_name = aws_key_pair.snaps-mini-pk.key_name

  tags = {
    Name = "tps-controller-${var.build_id}"
  }

  security_groups = [aws_security_group.tps.name]
  associate_public_ip_address = true

  provisioner "remote-exec" {
    inline = [
      "sudo echo 'tps-orchestrator/controller' > ~/motd",
    ]
  }

  # Remote connection info for remote-exec
  connection {
    host = self.public_ip
    type = "ssh"
    user = var.sudo_user
    private_key = file(var.private_key_file)
  }
}

# Tofino Model Switch Instances
resource "aws_instance" "tps-switch" {
  count = var.scenario_name == "full" ? var.num_switches_full : var.num_switches_single
  ami = var.tofino.ami
  instance_type = var.switch_instance_type
  key_name = aws_key_pair.snaps-mini-pk.key_name

  tags = {
    Name = "tps-switch-${var.build_id}"
  }

  security_groups = [aws_security_group.tps.name]
  associate_public_ip_address = false
}

# Network nodes
resource "aws_instance" "node" {
  count = var.scenario_name == "full" ? var.num_nodes_full : var.num_nodes_single

  ami = var.tofino.ami
  instance_type = var.node_instance_type
  key_name = aws_key_pair.snaps-mini-pk.key_name

  tags = {
    Name = "tps-node-${var.build_id}"
  }

  security_groups = [aws_security_group.tps.name]
  associate_public_ip_address = false
}
