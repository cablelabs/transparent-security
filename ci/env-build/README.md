# transparent-security Environment build
Readme for information on building a transparent-security environment

### Host Requirements

- Python 2.7 is installed
- The python-pip package has been installed
- The Python ansible >=2.7.5 package has been installed

### Install terraform

Download and install your binary for your platform from  https://www.terraform.io/downloads.html

### Setup and execute

An example file is in: transparent-security/docs/mininet-example.tfvars 

Copy transparent-securiyt/docs/example.tfvars to a working directory and 
make changes to adapt the file to your local environment.

This Terraform script has been designed to build a P4 environment on AWS.
The following variables are required:


* build_id: this value must be unique to ensure multiple jobs can be run
simultaneously from multiple hosts
* access_key: Amazon EC2 access key
* secret_key: Amazon EC2 secret key
* ec2_region: Amazon EC2 region
* env_type: {'mininet'|'tofino'}

The following variaiable are only used when running a tofine build and can
be skipped with a mininet environment.

* bf_sde_s3_bucket: when env_type is 'tofino', this is the bucket where your
Barefoot SDE tar file would be located
* bf_sde_version: when env_type is 'tofino', this is the version contained in
your associated s3 (Defaults and tested with '8.9.2', note that previous versions may not work) 
* public_key_file: Used to inject into the VM for SSH access with the user
'ubuntu' (defaults to ~/.ssh/id_rsa.pub)
* private_key_file: Used to access the VM via SSH with the user 'ubuntu'
(Defaults to ~/.ssh/id_rsa)


````
git clone https://github.com/cablelabs/transparent-security
cd transparent-security/ci/env-build
terraform init
terraform apply -auto-approve \
-var '{var name}={appropriate value}' &| -var-file={some tfvars file}
````

Example terraform command with updated variable file:
````
terraform apply -auto-approve -var-file=my-mininet.tfvars
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
terraform destroy -auto-approve \
-var '{var name}={appropriate value}' &| -var-file={some tfvars file}
````
