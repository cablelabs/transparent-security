# transparent-security CI

## Table of Contents

1. Introduction
2. Client system setup
3. [Optional] Create an OS instance for running the mininet simulator
4. Run minine simulator

## 1. Introduction

This document provides instructuions to:

1. Building a transparent-security environment on AWS
1. Setting up Mininet and AWS

## 2. Client system setup

When running builds and simulations this project reccomends running them on a cloud infrastructure.  These instructuion are using AWS EC2.  With minor changes these could be run on other cloud types.

You will use a local system for:

* Running Ansible and Terraform to orchestrate the simulator
* Downloading the Transparnet Secuirty source
* Configuring the input file

The local system can be Linux, Mac OS or Windows.  We provide examples for Linux.  This has also been testing on Mac OS.

### 2.1 Install dependences on local client

Install git, python-ansible and terrafrom.

#### 2.1.1 Install git

Instal the git client.

On Ubuntu:

```bash
sudo apt update
sudo apt install git
```

#### 2.1.2 Install Python Ansible

* Python 2.7 is installed
* The python-pip package has been installed
* The Python ansible >=2.7.5 package has been installed

Use Python-pip to install ansible >=2.7.5.

On Ubuntu run:

```bash
sudo apt update
sudo apt install python-pip
sudo pip install ansible
```

Validate the ansible version:

```bash
ansible --version
```

Example output:

```bash
ansible 2.9.2
.
.
.
  python version = 2.7.16 (default, Nov  9 2019, 05:55:08) [GCC 4.2.1 Compatible Apple LLVM 11.0.0 (clang-1100.0.32.4) (-macos10.15-objc-s
```

#### 2.1.2 Install Terraform

See terroaform docuementation for installation instructruction.

[Terraform Download page](https://www.terraform.io/downloads.html)

### 2.2. Download Transparent Secuirty from Git

Download the latest source from [Transparent Secuirty GitHub](https://github.com/cablelabs/transparent-security)

```bash
git clone https://github.com/cablelabs/transparent-security
```

Example output:

```bash
Cloning into 'transparent-security'...
.
.
.
Resolving deltas: 100% (554/554), done.
```

### 2.3. Obtain credentials to AWS

To use the directions, you will need an account on [AWS](https://aws.amazon.com/) with API access keys.

### 2.4 Customize the variable file for your environment

Copy the example variable file docs/mininet-example.tfvars to a working directory and make changes to adapt the file to your local environment.

| Variable         | Description                                                                                                                               | Type   | Example                                                 |
|------------------|-------------------------------------------------------------------------------------------------------------------------------------------|--------|---------------------------------------------------------|
| build_id         | This value must be unique to ensure multiple jobs  can be run simultaneously from multiple hosts                                          | string | build_id = "test-1"                                     |
| access_key       | Amazon EC2 access key                                                                                                                     | string | access_key = "AKIAIOSFODNN7EXAMPLE"                     |
| secret_key       | Amazon EC2 secret key                                                                                                                     | string | secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" |
| ec2_region       | Amazon EC2 region                                                                                                                         | string | ec2_region = "us-west-2"                                |
| public_key_file  | Used to inject into the VM for SSH access with the user'ubuntu' (defaults to ~/.ssh/id_rsa.pub)                                           | string | public_key_file = "~/.ssh/id_rsa.pub"                   |
| private_key_file | Used to access the VM via SSH with the user 'ubuntu' (defaults to ~/.ssh/id_rsa)                                                          | string | private_key_file = "~/.ssh/id_rsa"                      |
| env_type | The type of environemnt being built (only used for creating the environment)                                                          | string | env_type = "mininet"                      |
| mininet_ami | The AMI for the mininet environment (defaults to "ami-060d055b5ca40de8c"). Only used for running the simulator.                                         | string | mininet_ami = "ami-060d055b5ca40de8c"                      |
| run_daemons      | When 'True', the mininet host daemons will be started else not (defaults to 'True') Only used for running the simulator.                                                      | string | run_daemons = "True"                                    |

## 3. [Optional] Create an OS instance for running the mininet simulator

This step is optional if you are running on AWS and use the AMI provided by CableLabs.

Section 3.1 provides instructions for using Terraform to build an AMI on your AWS.

Section 3.2 provides instructions for building an image in another environemnt or on baremetal.

### 3.1. Build an AMI for running mininet on AWS

#### 3.1.1 Create VM with Terraform

This step will creat an VM on AWS, install all mininet dependencies and create an AMI.

```bash
cd transparent-security/automation/env-build
terraform init
terraform apply -auto-approve -var-file="/path/to/my-mininet.tfvars"
```

Sample Output:

```bash
aws_key_pair.transparent-security-mini-pk: Creating...
aws_security_group.transparent-security-img-sg: Creating...
aws_key_pair.transparent-security-mini-pk: Creation complete after 1s
.
.
.
Apply complete! Resources: 12 added, 0 changed, 0 destroyed.

Outputs:

ami-id = ami-0393652ac3fbc331e
ip = 34.211.114.181
```

Save the ami-id and it to your variables file.

#### 3.1.2 Remove the AMI for terraform state

Remove the AMI from the terrafrom state so that it will remain after destroying the VM.

```bash
terraform state rm aws_ami_from_instance.transparent-security-env-build
Removed aws_ami_from_instance.transparent-security-env-build
Successfully removed 1 resource instance(s).
```

#### 3.1.3 Clean up the VM used to create the AMI

This step will remove everything except the AMI that was used to create the VM.

```bash
terraform destroy -auto-approve -var-file="/path/to/my-mininet.tfvars"
```

Sample output:

```bash
aws_key_pair.transparent-security-mini-pk: Refreshing state... [id=terraform-20191213203053435500000001]
aws_security_group.transparent-security-img-sg: Refreshing state... [id=sg-057e54e0162c6251a]
.
.
.
Destroy complete! Resources: 4 destroyed.
```

## 4. Run minine simulator

Use the environment file create in section 2.4

### 4.1 Run terraform to launch the simulator on AWS.

```bash
cd transparent-security/automation/p4/mininet
terraform init
terraform apply -auto-approve -var-file="/path/to/my-mininet.tfvars"
```

Sample Output:

```bash
aws_key_pair.transparent-security-mini-pk: Creating...
aws_security_group.transparent-security-img-sg: Creating...
aws_key_pair.transparent-security-mini-pk: Creation complete after 5s
.
.
.
Apply complete! Resources: 12 added, 0 changed, 0 destroyed.

Outputs:

ip = 34.211.54.181
```

### 4.2 Obtain Deployment Information

```bash
# from transparent-security/automation/p4/mininet directory
terraform show
```

Sample output -

```bash
# aws_instance.transparent-security-mininet-integration:
resource "aws_instance" "transparent-security-mininet-integration" {
    ami                          =  
.
.
.
.
Outputs:

ip = "34.211.114.181"
```

### 4.3 SSH into EC2 Mininet VM

Login to the VM running the simulator.  Use the SSH kyes indicated in the variable file to login
to the VM.

```bash
# from transparent-security/automation/p4/mininet directory
ssh -i ubuntu@$(terraform output ip)
```

Sample output -

```bash
Welcome to Ubuntu 16.04.5 LTS (GNU/Linux 4.4.0-1075-aws x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  Get cloud support with Ubuntu Advantage Cloud Guest:
    http://www.ubuntu.com/business/services/cloud

149 packages can be updated.
89 updates are security updates.

New release '18.04.3 LTS' available.
Run 'do-release-upgrade' to upgrade to it.


Last login: Wed Dec 11 22:39:13 2019 from 127.0.0.1
ubuntu@ip-172-31-15-5:~$
```

Upgrading to a newer version of Ubuntu isn't currently supported.  Do so at your own risk.

### 4.4. Development and debugging of Python

The playbooks will be installing the python code located in the trans_sec
directory into the VM's Python runtime in place so any changes there will be
realized immediately.

### 4.5. Cleanup the simulation environment

This will remove the VM and other artifacts created when it was deployed.

```bash
# from transparent-security/automation/p4/mininet directory
terraform destroy -auto-approve -var-file="/path/to/my-mininet.tfvars"
```

Sample output:

```bash
.
.
Destroy complete! Resources: 12 destroyed.

Process finished with exit code 0
```
