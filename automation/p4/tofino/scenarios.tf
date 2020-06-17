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

resource "null_resource" "transparent-security-run-senario-tests" {
  depends_on = [null_resource.tps-tofino-setup-nodes]

  provisioner "remote-exec" {
    inline = [
      "sudo pip install ansible",
      "${var.ANSIBLE_CMD} -i ${var.remote_inventory_file} ${var.remote_scenario_pb_dir}/${var.scenario_name}/${var.test_case}.yml --extra-vars='run_mode=remote'",
    ]
  }

  connection {
    host        = aws_instance.orchestrator.public_ip
    type        = "ssh"
    user        = var.sudo_user
    private_key = file(var.private_key_file)
  }
}
