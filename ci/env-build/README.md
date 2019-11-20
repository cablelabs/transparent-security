# transparent-security Environment build
Readme for information on building a transparent-security environment

### Host Requirements

- Python 2.7 is installed
- The python-pip package has been installed
- The Python ansible >=2.7.5 package has been installed

### Install terraform

Download and install your binary for your platform from  https://www.terraform.io/downloads.html

### Setup and execute

This Terraform script has been designed to build a P4 environment on AWS.
The following variables are required:

1. build_id: this value must be unique to ensure multiple jobs can be run
simultaneously from multiple hosts
1. access_key: Amazon EC2 access key
1. secret_key: Amazon EC2 secret key
1. ec2_region: Amazon EC2 region
1. public_key_file: Used to inject into the VM for SSH access with the user
'ubuntu' (defaults to ~/.ssh/id_rsa.pub)
1. private_key_file: Used to access the VM via SSH with the user 'ubuntu'
(Defaults to ~/.ssh/id_rsa)

````
git clone https://github.com/cablelabs/transparent-security
git clone https://github.com/cablelabs/snaps-config
cd transparent-security/ci/env-build
terraform init
terraform apply -var-file={dir}/snaps-config/aws/snaps-ci.tfvars \
-auto-approve \
-var '{var name}={appropriate value}' &| -var-file={some tfvars file}
````

### Obtain Deployment Information
````
# from transparent-security/ci/env-build directory
terraform show
````

### Obtain EC2 Instance IP
````
# from transparent-security/ci/env-build directory
terraform output ip
````

### SSH into EC2 Mininet VM
````
# from transparent-security/ci/env-build directory
ssh -i ubuntu@$(terraform output ip)
````

### Cleanup
````
# from transparent-security/ci/env-build directory
terraform destroy -var-file=~/snaps-config/aws/snaps-ci.tfvars \
-auto-approve -var \
-var '{var name}={appropriate value}' &| -var-file={some tfvars file}
````
