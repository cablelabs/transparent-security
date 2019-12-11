# transparent-security Mininet integration setup on AWS
Readme for information on how to execute transparent-security integration tests

### Host Requirements

- Python 2.7 is installed
- The python-pip package has been installed
- The Python ansible >=2.7.5 package has been installed

### Install terraform

Download and install your binary for your platform from  https://www.terraform.io/downloads.html

### Setup and execute

This Terraform script has been designed to run and execute tests for P4
programs on mininet on AWS. The following variables are required or have
defaults that may cause issues:


1. build_id: this value must be unique to ensure multiple jobs can be run
simultaneously from multiple hosts
1. access_key: Amazon EC2 access key
1. secret_key: Amazon EC2 secret key
1. ec2_region: Amazon EC2 region
1. mininet_ami: The image ID created from the env-build terraform script
1. public_key_file: Used to inject into the VM for SSH access with the user
'ubuntu' (defaults to ~/.ssh/id_rsa.pub)
1. private_key_file: Used to access the VM via SSH with the user 'ubuntu'
(Defaults to ~/.ssh/id_rsa)
1. run_daemons: When 'True', the mininet host daemons will be started else not
(Defaults 'True')

````
git clone https://github.com/cablelabs/transparent-security
cd transparent-security/ci/p4/mininet
terraform init
terraform apply \
-auto-approve \
-var '{var name}={appropriate value}' &| -var-file={some tfvars file}
````
Note: Refer the example.tfvars in transparent-security/docs   
Example: 
````
terraform apply -auto-approve -var-file=transparent-security/docs/example.tfvars -var build_id=test-vm
````
### Obtain Deployment Information
````
# from transparent-security/ci/p4/mininet directory
terraform show
````

### Obtain EC2 Instance IP
````
# from transparent-security/ci/p4/mininet directory
terraform output ip
````

### SSH into EC2 Mininet VM
````
# from transparent-security/ci/p4/mininet directory
ssh -i ubuntu@$(terraform output ip)
````

### Development and debugging of Python
The playbooks will be installing the python code located in the trans_sec
directory into the VM's Python runtime in place so any changes there will be
realized immediately.

### Cleanup
````
# from transparent-security/ci/p4/mininet directory
terraform destroy -var-file=~/snaps-config/aws/snaps-ci.tfvars \
-auto-approve \
-var '{var name}={appropriate value}' &| -var-file={some tfvars file}
````
