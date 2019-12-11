# transparent-security CI

### Table of Contents
1. Introduction
2. Host Requirements
3. Install Terraform
4. Setup and Execute  
   4.1. CI Environment Build  
   4.2. Mininet
5. Obtain deployment information
6. Obtain EC2 instance IP
7. Development and debugging of Python
8. Cleanup

### 1. Introduction
Readme for information on -
1. Building a transparent-security environment
2. Setting up Mininet

### 2. Host Requirements

- Python 2.7 is installed
- The python-pip package has been installed
- The Python ansible >=2.7.5 package has been installed

### 3. Install Terraform

Download and install your binary for your platform from  https://www.terraform.io/downloads.html

### 4. Setup and Execute

  ### 4.1. CI Environment Build

An example file is in: transparent-security/docs/env-build-example.tfvars 

Copy transparent-securiyt/docs/env-build-example.tfvars to a working directory and 
make changes to adapt the file to your local environment.

This Terraform script has been designed to build a P4 environment on AWS.
The following variables are required:

| Variable         | Description                                                                                                                               | Type   | Example                                                 |
|------------------|-------------------------------------------------------------------------------------------------------------------------------------------|--------|---------------------------------------------------------|
| build_id         | This value must be unique to ensure multiple jobs  can be run simultaneously from multiple hosts                                          | string | build_id = "test-1"                                     |
| access_key       | Amazon EC2 access key                                                                                                                     | string | access_key = "AKIAIOSFODNN7EXAMPLE"                     |
| secret_key       | Amazon EC2 secret key                                                                                                                     | string | secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" |
| ec2_region       | Amazon EC2 region                                                                                                                         | string | ec2_region = "us-west-2"                                |
| env_type         | The type of environment being used. Could be "mininet" or "tofino".                                                                       | string | env_type = "mininet"                                    |
| public_key_file  | Used to inject into the VM for SSH access with the user'ubuntu' (defaults to ~/.ssh/id_rsa.pub)                                           | string | public_key_file = "~/.ssh/id_rsa.pub"                   |
| private_key_file | Used to access the VM via SSH with the user 'ubuntu' (defaults to ~/.ssh/id_rsa)                                                          | string | private_key_file = "~/.ssh/id_rsa"                      |
| bf_sde_s3_bucket | Used when env_type="tofino". Points to the S3 bucket with the Barefoot SDE tar file                                                        | string | bf_sde_s3_bucket = "Barefoot"                           |
| bf_sde_version   | Used when env_type="tofino". Barefoot SDE version in the S3 bucket (defaults and tested with '8.9.2'). Note: Previous versions may not work | string | bf_sde_version = "8.9.2"                                |

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
terraform apply -auto-approve -var-file=env-build.tfvars
````

  ### 4.2. Mininet 
  
An example file is in: transparent-security/docs/mininet-example.tfvars 

Copy transparent-securiyt/docs/mininet-example.tfvars to a working directory and 
make changes to adapt the file to your local environment.

This Terraform script has been designed to run and execute tests for P4
programs on mininet on AWS. The following variables are required or have
defaults that may cause issues:

| Variable         | Description                                                                                                                               | Type   | Example                                                 |
|------------------|-------------------------------------------------------------------------------------------------------------------------------------------|--------|---------------------------------------------------------|
| build_id         | this value must be unique to ensure multiple jobs  can be run simultaneously from multiple hosts                                          | string | build_id = "test-mininet"                                     |
| access_key       | Amazon EC2 access key                                                                                                                     | string | access_key = "AKIAIOSFODNN7EXAMPLE"                     |
| secret_key       | Amazon EC2 secret key                                                                                                                     | string | secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" |
| ec2_region       | Amazon EC2 region                                                                                                                         | string | ec2_region = "us-west-2"                                |
| run_daemons      | When 'True', the mininet host daemons will be started else not (defaults to 'True')                                                       | string | run_daemons = "True"                                    |
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
### 5. Obtain Deployment Information
````
# from transparent-security/ci/p4/mininet directory
terraform show
````

### 6. Obtain EC2 Instance IP
````
# from transparent-security/ci/p4/mininet directory
terraform output ip
````

### SSH into EC2 Mininet VM
````
# from transparent-security/ci/p4/mininet directory
ssh -i ubuntu@$(terraform output ip)
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
