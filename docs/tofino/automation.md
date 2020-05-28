# transparent-security automation for the tofino-model

The scripts outlined here have been designed to be executed within a CI server


### Getting started
Please see "Client system setup" in ../BUILD.md

Please uses these variables instead
Copy the example variable file docs/tofino-example.tfvars to a working
directory and make changes to adapt the file to your local environment.

| Variable         | Description                                                                                                                               | Type   | Example                                                 |
|------------------|-------------------------------------------------------------------------------------------------------------------------------------------|--------|---------------------------------------------------------|
| build_id         | This value must be unique to ensure multiple jobs  can be run simultaneously from multiple hosts                                          | string | build_id = "test-1"                                     |
| access_key       | Amazon EC2 access key                                                                                                                     | string | access_key = "AKIAIOSFODNN7EXAMPLE"                     |
| secret_key       | Amazon EC2 secret key                                                                                                                     | string | secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" |
| ec2_region       | Amazon EC2 region                                                                                                                         | string | ec2_region = "us-west-2"                                |
| public_key_file  | Used to inject into the VM for SSH access with the user'ubuntu' (defaults to ~/.ssh/id_rsa.pub)                                           | string | public_key_file = "~/.ssh/id_rsa.pub"                   |
| private_key_file | Used to access the VM via SSH with the user 'ubuntu' (defaults to ~/.ssh/id_rsa)                                                          | string | private_key_file = "~/.ssh/id_rsa"                      |
| env_type         | The type of environemnt being built (only used for creating the environment)                                                              | string | env_type = "tofino"                                    |
| tofino_ami       | The AMI for the tofino environment (defaults to "ami-060d055b5ca40de8c"). Only used for running the simulator.                           | string | tofino_ami = "ami-060d055b5ca40de8c"                   |

### Build AMI for running the tofino-model on AWS

#### Create VM with Terraform

Create s3 bucket using the same AWS credentials for the BF-SDE tar/tgz
bf_sde_s3_bucket
This step will creat an VM on AWS, install all Tofino 9.2.0 dependencies and create an AMI.

```bash
cd transparent-security/automation/p4/env-build
terraform init
terraform apply -auto-approve -var-file="/path/to/my-tofino.tfvars -var env_type=tofino -var bf_sde_s3_bucket={bucket name}"
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

### Remove the AMI for terraform state

Remove the AMI from the terraform state so that it will remain after destroying the VM.

```bash
terraform state rm aws_ami_from_instance.transparent-security-env-build
Removed aws_ami_from_instance.transparent-security-env-build
Successfully removed 1 resource instance(s).
```

### Clean up the VM used to create the AMI

This step will remove everything except the AMI that was used to create the VM.

```bash
terraform destroy -auto-approve -var-file="/path/to/my-tofino.tfvars"
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

## Create a virtual Tofino switch environment (using Terraform)

Use the environment file created in section 2.4

### Run terraform to launch the cluster on AWS.

Variable file must also contain as the default is tied to a CableLabs AWS account:
```hcl-terraform
variable "tofino" {
  default = {
    sde_version = "9.2.0"
    ami = "{{ your ami-version }}"
  }
}
```

```bash
cd transparent-security/automation/p4/tofino
terraform init
terraform apply -auto-approve -var-file="/path/to/my-tofino.tfvars"
```

Sample Output:

```bash
aws_key_pair.transparent-security-tofino-pk: Creating...
aws_security_group.transparent-security-img-sg: Creating...
aws_key_pair.transparent-security-tofino-pk: Creation complete after 5s
.
.
.
Apply complete! Resources: 22 added, 0 changed, 0 destroyed.

Outputs:

ip = 34.211.54.181
```

### 4.3 SSH into EC2 orchestrator/controller machine

Login to the VM running the simulator.  Use the SSH keys indicated in the variable file to login
to the VM.

```bash
# from transparent-security/automation/p4/tofino directory
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

### Cleanup the simulation environment

This will remove the VM and other artifacts created when it was deployed.

```bash
# from transparent-security/automation/p4/tofino directory
terraform destroy -auto-approve -var-file="/path/to/my-tofino.tfvars"
```

Sample output:

```bash
.
.
Destroy complete! Resources: 12 destroyed.

Process finished with exit code 0
```

### What is deployed
Controller/Orchestrator node with outside access
9 network nodes
5 Tofino switches