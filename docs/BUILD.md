# transparent-security CI

## Table of Contents

1. Introduction
2. [Optional] Create an OS instance for running the mininet simulator
3. Run minine simulator
4. Obtain EC2 instance IP
5. Development and debugging of Python
6. Cleanup

## 1. Introduction

This document provides instructuions to:

1. Building a transparent-security environment on AWS
1. Setting up Mininet and AWS

## 2. [Optional] Create an OS instance for running the mininet simulator

This step is optional if you are running on AWS and use the AMI provided by CableLabs.

Section 4.1 provides instructions for using Terraform to build an AMI on your AWS.

Section 4.2 provides instructions for building an image in another environemnt or on baremetal.

### 2.1. Build an AMI for running mininet on AWS

#### 1. Clone the transparent-security repository

```bash
git clone https://github.com/cablelabs/transparent-security
```

#### 2. Create a variable file for your environment

Copy the example variable file transparent-securiyt/docs/env-build-example.tfvars to a working directory and make changes to adapt the file to your local environment.

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

#### 3. Install dependences on your local system

This can be any system capable of connecting to AWS and running Terraform and Ansible to build an AMI with the dependencies needed to run the mininet simulator.

- Python 2.7 is installed
- The python-pip package has been installed
- The Python ansible >=2.7.5 package has been installed

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

#### 4. Install Terraform

[Terraform Download page](https://www.terraform.io/downloads.html)

#### 5. Create the AMI with terraform

This step will creat an VM on AWS, install all mininet dependencies and create an AMI.

```bash
cd transparent-security/ci/env-build
terraform init
terraform apply -auto-approve -var-file=env-build.tfvars
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

Save the ami-id, this will be used when running simulations.

#### 6. Remove the AMI for terraform state

Remove the AMI from the terrafrom state so that it will remain after destroying the VM.

```bash
terraform state rm aws_ami_from_instance.transparent-security-env-build
Removed aws_ami_from_instance.transparent-security-env-build
Successfully removed 1 resource instance(s).
```

#### 7. Destroy the VM and other artificats

```bash
terraform destroy -auto-approve -var-file="../../my-mininet.tfvars"
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

### 3. Run minine simulator

If you create an evironment 

An example file is in: transparent-security/docs/mininet-example.tfvars

Copy transparent-securiyt/docs/mininet-example.tfvars to a working directory and 
make changes to adapt the file to your local environment.

This Terraform script has been designed to run and execute tests for P4
programs on mininet on AWS. The following variables are required or have
defaults that may cause issues:

| Variable         | Description                                                                                                                               | Type   | Example                                                 |
|------------------|-------------------------------------------------------------------------------------------------------------------------------------------|--------|---------------------------------------------------------|
| build_id         | This value must be unique to ensure multiple jobs  can be run simultaneously from multiple hosts                                          | string | build_id = "test-mininet"                                     |
| access_key       | Amazon EC2 access key                                                                                                                     | string | access_key = "AKIAIOSFODNN7EXAMPLE"                     |
| secret_key       | Amazon EC2 secret key                                                                                                                     | string | secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" |
| ec2_region       | Amazon EC2 region                                                                                                                         | string | ec2_region = "us-west-2"                                |
| public_key_file  | Used to inject into the VM for SSH access with the user'ubuntu' (defaults to ~/.ssh/id_rsa.pub)                                           | string | public_key_file = "~/.ssh/id_rsa.pub"                   |
| private_key_file | Used to access the VM via SSH with the user 'ubuntu' (defaults to ~/.ssh/id_rsa)                                                          | string | private_key_file = "~/.ssh/id_rsa"                      |

````
git clone https://github.com/cablelabs/transparent-security
cd transparent-security/ci/p4/mininet
terraform init
terraform apply \
-auto-approve \
-var '{var name}={appropriate value}' &| -var-file={some tfvars file}
````
Example terraform command with updated variable file:
````
terraform apply -auto-approve -var-file=mininet.tfvars
````

Sample Output
````
aws_key_pair.transparent-security-mini-pk: Creating...
aws_security_group.transparent-security-img-sg: Creating...
aws_key_pair.transparent-security-mini-pk: Creation complete after 5s
.
.
.
Apply complete! Resources: 12 added, 0 changed, 0 destroyed.

Outputs:

ip = 34.211.54.181
````
### 5. Obtain Deployment Information
````
# from transparent-security/ci/p4/mininet directory
terraform show
````
Sample output - 
````
# aws_instance.transparent-security-mininet-integration:
resource "aws_instance" "transparent-security-mininet-integration" {
    ami                          =  
.
.
.
.
Outputs:

ip = "34.211.114.181"
````
### 6. Obtain EC2 Instance IP
````
# from transparent-security/ci/p4/mininet directory
terraform output ip
````
Sample output - 
````
34.211.114.181
````
### SSH into EC2 Mininet VM
````
# from transparent-security/ci/p4/mininet directory
ssh -i ubuntu@$(terraform output ip)
````
Sample output - 
````
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
````
### 7. Development and debugging of Python
The playbooks will be installing the python code located in the trans_sec
directory into the VM's Python runtime in place so any changes there will be
realized immediately.

### 8. Cleanup
CI environment build - 
````
# from transparent-security/ci/env-build directory
terraform destroy -auto-approve \
-var '{var name}={appropriate value}' &| -var-file={some tfvars file}
````
Mininet - 
````
# from transparent-security/ci/p4/mininet directory
terraform destroy -auto-approve \
-var '{var name}={appropriate value}' &| -var-file={some tfvars file}
````
Sample output - 
````
.
.
Destroy complete! Resources: 12 destroyed.

Process finished with exit code 0
````