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

# AWS Credentials
provider "aws" {
  access_key = var.access_key
  secret_key = var.secret_key
  region = var.ec2_region
}

# Note: Script will fail if another process is leveraging the same build_id
resource "aws_security_group" "transparent-security-img-sg" {
  name = "transparent-security-${var.scenario_name}-${var.build_id}"
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
    from_port = 22
    to_port = 22
    protocol = "tcp"
  }

  ingress {
    cidr_blocks = ["0.0.0.0/0"]
    from_port = 50051
    to_port = 50056
    protocol = "tcp"
  }

  // Terraform removes the default rule
  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# AWS EC2 Instance Public Key
resource "aws_key_pair" "transparent-security-pk" {
  public_key = file(var.public_key_file)
}
