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
  ami = var.p4_arch == "tna" ? var.tofino.bfrt_ami : var.tofino.p4rt_ami
}

# Orchestrator/SDN Controller Instance
resource "aws_instance" "orchestrator" {
  ami = local.ami
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
    user = var.orch_user
    private_key = file(var.private_key_file)
  }
}

# Determine switch and node count
locals {
  switch_count = var.scenario_name == "full" ? var.num_switches_full : var.scenario_name == "lab_trial" ? var.num_switches_lab_trial : var.num_switches_single
  node_count = var.scenario_name == "full" ? var.num_nodes_full : var.scenario_name == "lab_trial" ? var.num_nodes_lab_trial : var.num_nodes_single
}

# Tofino Model Switch Instances
resource "aws_instance" "tps-switch" {
  count = local.switch_count
  availability_zone = var.availability_zone
  ami = local.ami
  instance_type = var.switch_instance_type
  key_name = aws_key_pair.snaps-mini-pk.key_name

  tags = {
    Name = "tps-switch-${var.build_id}"
  }

  security_groups = [aws_security_group.tps.name]
  associate_public_ip_address = true
}

# Third octet of the subnet IPv4 value
resource "random_integer" "tunnel_subnet_3" {
  min = 100
  max = 220
}

# Create subnets for the GRE tunnels
resource "aws_subnet" "tunnel_1_subnet" {
  availability_zone = var.availability_zone
  cidr_block = "${var.vpc_subnet_prfx}.${random_integer.tunnel_subnet_3.result}.0/24"
  vpc_id = var.vpc_id
}

locals {
  switch_inst_ids = tolist([
    for switch_inst in aws_instance.tps-switch: {
      id = switch_inst.id
    }
  ])
}

resource "aws_network_interface" "switch_tun_1" {
  depends_on = [aws_instance.tps-switch, aws_subnet.tunnel_1_subnet]
  count = local.switch_count
  subnet_id = aws_subnet.tunnel_1_subnet.id
  security_groups = [aws_security_group.tps-internal.id]
  tags = {
    Name = "tps-switch-tun1-${var.build_id}"
  }
  attachment {
    device_index = 1
    instance = aws_instance.tps-switch[count.index].id
  }
}

# Network nodes
resource "aws_instance" "node" {
  count = local.node_count
  availability_zone = var.availability_zone
  ami = local.ami
  instance_type = var.node_instance_type
  key_name = aws_key_pair.snaps-mini-pk.key_name

  tags = {
    Name = "tps-node-${var.build_id}"
  }

  security_groups = [aws_security_group.tps.name]
  associate_public_ip_address = false
}

resource "aws_network_interface" "node_tun_1" {
  depends_on = [aws_instance.node, aws_subnet.tunnel_1_subnet]
  count = local.node_count
  subnet_id = aws_subnet.tunnel_1_subnet.id
  security_groups = [aws_security_group.tps-internal.id]
  tags = {
    Name = "tps-node-tun1-${var.build_id}"
  }
  attachment {
    device_index = 1
    instance = aws_instance.node[count.index].id
  }
}

# Network nodes
resource "aws_instance" "ae" {
  availability_zone = var.availability_zone
  ami = var.siddhi_ae_ami
  instance_type = var.ae_instance_type
  key_name = aws_key_pair.snaps-mini-pk.key_name

  tags = {
    Name = "tps-siddhi-ae-${var.build_id}"
  }
  security_groups = [aws_security_group.tps.name]
  associate_public_ip_address = true
}

resource "aws_network_interface" "ae_tun_1" {
  depends_on = [aws_instance.ae, aws_subnet.tunnel_1_subnet]
  subnet_id = aws_subnet.tunnel_1_subnet.id
  security_groups = [aws_security_group.tps-internal.id]
  tags = {
    Name = "tps-ae-tun1-${var.build_id}"
  }
  attachment {
    device_index = 1
    instance = aws_instance.ae.id
  }
}
