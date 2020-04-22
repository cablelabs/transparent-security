# transparent-security automation

The scripts outlined here have been designed to be executed within a CI server

## Table of Contents

1. Introduction
2. Client system setup
3. [Optional] Create an OS instance for running the mininet simulator
4. Run mininet simulator (using Terraform)
5. [Optional] Run mininet simulator (using ansible)
6. [Optional] Run mininet simulator on a local VM
7. Using Mininet

## 1. Introduction

This document provides instructuions to:

1. Building a transparent-security environment on AWS
1. Setting up Mininet and AWS

## 2. Client system setup

When running builds and simulations this project recommends running them on a cloud infrastructure.  These instructions are using AWS EC2.  With minor changes these could be run on other cloud types.

You will use a local system for:

* Running Ansible and Terraform to orchestrate the simulator
* Downloading the Transparent Security source
* Configuring the input file

The local system can be Linux, Mac OS or Windows.  We provide examples for Linux.  This has also been testing on Mac OS.

### 2.1 Install dependencies on local client

Install git, python-ansible and terraform.

#### 2.1.1 Install git

Install the git client.

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

See terraform documentation for installation instructions.

[Terraform Download page](https://www.terraform.io/downloads.html)

### 2.2. Download Transparent Secuirty from Git

Download the latest source from [Transparent Security GitHub](https://github.com/cablelabs/transparent-security)

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
| env_type         | The type of environemnt being built (only used for creating the environment)                                                              | string | env_type = "mininet"                                    |
| mininet_ami      | The AMI for the mininet environment (defaults to "ami-060d055b5ca40de8c"). Only used for running the simulator.                           | string | mininet_ami = "ami-060d055b5ca40de8c"                   |
| create_ami       | When 'yes', the an EC2 image (AMI) will be created.                                                                                       | string | create_ami = "yes"                                      |

## 3. [Optional] Create an OS instance for running the mininet simulator

This step is optional if you are running on AWS and use the AMI provided by CableLabs.

Section 3.1 provides instructions for using Terraform to build an AMI on your AWS.

Section 3.2 provides instructions for building an image in another environment or on baremetal.

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

Remove the AMI from the terraform state so that it will remain after destroying the VM.

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

## 4. Run mininet simulator (using Terraform)

Use the environment file created in section 2.4

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

Login to the VM running the simulator.  Use the SSH keys indicated in the variable file to login
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

## 5. [Optional] Run mininet simulator (using ansible)

### 5.1. Launch an AWS instance using pre-built AMI

- From the EC2 dashboard, launch a new instance with the AMI provided by CableLabs.  
- Configure the security group for the instance as follows-  

|       Type     | Protocol | Port Range |   Source  |
|:---------------:|:--------:|:----------:|:---------:|
| Custom TCP Rule |    TCP   |    8080    | 0.0.0.0/0 |
|       SSH       |    TCP   |     22     | 0.0.0.0/0 |
| Custom TCP Rule |    TCP   |    3000    | 0.0.0.0/0 |
|      HTTPS      |    TCP   |     443    | 0.0.0.0/0 |

- Review and launch the instance. When prompted, generate a new key-pair and save it on the local machine.

### 5.2. Create a local ansible inventory

Generate your local ansible inventory file with the following command where
<local-inventory-file> is the name of the output inventory file to be used
in step 5.4 below and <mininet-host-ip> is the IP of the host you want to setup.
```bash
ansible-playbook transparent-security/playbooks/mininet/local_inventory.yml \
--extra-vars "public_ip=<mininet-host-ip> local_inventory=<local-inventory-file>"
```

### 5.3. Create and inject own SSH keys

- Login to the remote VM
```bash
ssh -i <saved key-pair> ubuntu@<public IP of VM>
```
- Create and inject SSH keys to be able to access the mininet hosts
```bash
ssh-keygen -t rsa -N '' -f ~/.ssh/id_rsa
touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
```

### 5.4. Setup transparent-security directory and install dependencies on the remote VM

- On the local machine, run the following command to setup the mininet host - 
```bash
export ANSIBLE_HOST_KEY_CHECKING=False
ansible-playbook -u ubuntu -i <local-inventory-file> transparent-security/playbooks/mininet/setup_host.yml --key-file ~/.ssh/id_rsa
```

### 5.5. Start mininet simulation

- On the remote VM, install ansible before proceeding to begin simulation.
```bash
sudo pip install ansible
export ANSIBLE_HOST_KEY_CHECKING=False
ansible-playbook -u ubuntu -i transparent-security.ini transparent-security/playbooks/mininet/setup_mininet.yml
```
Note - The transparent-security.ini refers to the inventory file on the remote machine which is generated in Step 5.4.

### 5.6. Test with an attack scenario

- On the remote VM, execute the attack scenario to validate attack detection and mitigation.  
- To use the sample scenario provided by CableLabs, run the following command on the remote VM -
```bash
export ANSIBLE_HOST_KEY_CHECKING=False
# run_mode denotes whether to run the tests on the localhost (faster packet generation) or directly on the mininet hosts (more accurate architecture but slow)
ansible-playbook -u ubuntu -i transparent-security.ini transparent-security/playbooks/scenarios/full/all.yml --extra-vars="run_mode=<'remote'|'local')>
```
Note - Refer the Wiki page [Attack Scenario](https://github.com/cablelabs/transparent-security/wiki/2.-Attack-Scenario) for a 
detailed explanation of the attack scenario.

## 6. [Optional] Run mininet simulator on a local VM

For this purpose, we use a Ubuntu 16.04 VirtualBox VM running on the local machine. 

### 6.1. Setup the local VM

- The network settings for the VM would have to allow access to the internet (to install
dependencies) and a channel for communication with the local machine.
    - Bridged Adapter
    - Host-only Adapter

- Enable SSH on the VM and verify the SSH service to be active
```bash
sudo apt-get install openssh-server
sudo service ssh status
```

- Allow passwordless sudo by editing the /etc/sudoers file
```bash
sudo visudo
%sudo  ALL=(ALL:ALL) NOPASSWD: ALL
```
- Install Python packages
```bash
sudo apt-get update
sudo apt-get install python2.7 -y
sudo ln /usr/bin/python2.7 /usr/bin/python
```
- Create and inject SSH keys to be able to access the mininet hosts
```bash
ssh-keygen -t rsa -N '' -f ~/.ssh/id_rsa
touch ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
cat ~/.ssh/id_rsa.pub >> ~/.ssh/authorized_keys
```

### 6.2. Setup the local machine

- Copy the SSH key to the VM. On the local machine,
```bash
ssh-copy-id -i <public-key-file> VM_user@VM_host
```

- Create a inventory file on the local machine to configure variables and VM IP address.  
Note - Copy the example inventory file docs/example-local-inventory.ini to a working directory and
 make changes to adapt the file to your local environment.
 
### 6.3. Build the environment to run mininet simulation

- On the local machine, run the env_build.yml to install the necessary software packages to run mininet.
```bash
export ANSIBLE_HOST_KEY_CHECKING=False; ansible-playbook -u ubuntu -i ~/variables.ini playbooks/mininet/env-build.yml
```
Note - The env-build approximately takes 45-60 minutes to finish.

### 6.4. Setup transparent-security directory and install dependencies on the VM
         
 - On the local machine, run the following command to create the inventory file
 for setting up the mininet host:
 ```bash
ansible-playbook transparent-security/playbooks/mininet/local_inventory.yml \
--extra-vars "public_ip=<mininet-host-ip> local_inventory=<local-inventory-file>"
 ```

 - On the local machine, run the following command to setup the mininet host:
 ```bash
 export ANSIBLE_HOST_KEY_CHECKING=False
 ansible-playbook -u ubuntu -i <local-inventory-file> transparent-security/playbooks/mininet/setup_host.yml --key-file ~/.ssh/id_rsa
 ```
### 6.5. Start mininet simulation

- On the VM, install ansible before proceeding to begin simulation.
```bash
sudo pip install ansible
export ANSIBLE_HOST_KEY_CHECKING=False
ansible-playbook -u ubuntu -i transparent-security.ini transparent-security/playbooks/mininet/setup_mininet.yml
```
Note - The transparent-security.ini refers to the inventory file on the remote machine which is generated in Step 6.4.

### 6.6. Test with the UDP Flood attack scenario

- On the VM, execute the attack scenario to validate attack detection and mitigation.  
- To use the sample scenario provided by CableLabs, run the following command on the remote VM -
```bash
export ANSIBLE_HOST_KEY_CHECKING=False
# run_mode denotes whether to run the tests on the localhost (faster packet generation) or directly on the mininet hosts (more accurate architecture but slow)
ansible-playbook -u ubuntu -i transparent-security.ini transparent-security/playbooks/scenarios/full/all.yml --extra-vars="run_mode=<'remote'|'local')>
```
Note - Refer the Wiki page [Attack Scenario](https://github.com/cablelabs/transparent-security/wiki/2.-Attack-Scenario) for a 
detailed explanation of the attack scenario.

## 7. Using Mininet

- Refer the Wiki page [Using Mininet](https://github.com/cablelabs/transparent-security/wiki/3.-Using-Mininet) for
information on the default mininet architecture, how to access devices and capture packet-level data.
