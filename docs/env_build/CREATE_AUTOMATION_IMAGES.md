# transparent-security automation for the tofino-model

The scripts outlined here have been designed to be executed within a CI server


### Getting started
Below are the variables used by the env_build CI automation scripts.

| Variable         | Description                                                                                                                               | Type   | Example                                                 |
|------------------|-------------------------------------------------------------------------------------------------------------------------------------------|--------|---------------------------------------------------------|
| build_id         | This value must be unique to ensure multiple jobs  can be run simultaneously from multiple hosts            | string | build_id = "example-1"                                  |
| access_key       | Amazon EC2 access key                                                                                       | string | access_key = "AKIAIOSFODNN7EXAMPLE"                     |
| secret_key       | Amazon EC2 secret key                                                                                       | string | secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" |
| ec2_region       | Amazon EC2 region                                                                                           | string | ec2_region = "us-west-2" (default)                      |
| public_key_file  | Used to inject into the VM for SSH access with the user'ubuntu' (defaults to ~/.ssh/id_rsa.pub)             | string | public_key_file = "~/.ssh/id_rsa.pub" (default)         |
| private_key_file | Used to access the VM via SSH with the user 'ubuntu' (defaults to ~/.ssh/id_rsa)                            | string | private_key_file = "~/.ssh/id_rsa" (default)            |
| env_type         | The type of environment being built (only used for creating the environment)                                | string | env_type = {"tofino"|"siddhi"} (default="tofino")       |
| create_ami       | When 'yes', the Terraform script will create a new AMI                                                      | string | create_ami = "no" (default)                             |
| bf_sde_version   | When this value will be used to obtaining the BF-SDE version                                                | string | bf_sde_version = "9.2.0" (default)                      |
| bf_sde_profile   | The BF-SDE profile name to install                                                                          | string | bf_sde_profile = "p416_examples_profile" (default)      |
| bf_sde_s3_bucket | The S3 bucket in which the BF SDE tar file lives (named bf-sde-{version}.tar)                               | string | bf_sde_s3_bucket = "EXAMPLE_S3_BUCKET"                  |

### Build AMIs for running the tofino-model and Siddhi AE on AWS

#### Create Tofino BF-SDE EC2 image with Terraform

##### Install Terraform
https://www.terraform.io/downloads.html

##### Upload BF-SDE archive
Create s3 bucket and upload the BF-SDE tar/tgz using the same AWS credentials.

##### Configure
Please see the following example Terraform Variable files to create the files
to hold the Terraform program arguments via the  --var-file command line option
in the "Execute" section below.

- [my-automation-base.tfvars template](../terraform/automation-base.example.tfvars)
- [my-tofino-build.tfvars template](../terraform/tofino-build.example.tfvars)
- [my-siddhi-maven-build.tfvars template](../terraform/siddhi-maven-build.example.tfvars)

##### Build Tofino image
This step will create an VM on AWS, install all Tofino 9.2.0 dependencies,
then create an AMI. (note: this process will take ~90 min to complete)

```bash
cd transparent-security/automation/p4/env-build
terraform init
terraform apply -auto-approve -var-file="my-automation-base.tfvars -var-file="my-tofino-build.tfvars" -var build_id={i.e. "my-build-x"}"
```

##### Build Siddhi Maven image
This step will create an VM on AWS, install everything required to run Siddhi
with the udp & p4-trpt extensions and Kafka. (note: this image is only required
for the "lab_trial" p4/tofino scenario and will take ~30 min to complete)

```bash
cd transparent-security/automation/p4/env-build
terraform init
terraform apply -auto-approve -var-file="my-automation-base.tfvars -var-file="my-siddhi-maven-build.tfvars" -var build_id={i.e. "my-build-y"}"
```

##### Sample output from the environment build terraform script
Sample Output:

```bash
.
.
.
Apply complete! Resources: 5 added, 0 changed, 0 destroyed.

Outputs:

ami-id = ami-xxx
ip = xx.xx.xx.xx
```

Save the ami-ids from each run to be used for running the p4/tofino automation scripts.

### Remove the AMI for terraform state

Remove the AMI from terraform state so that it will remain after destroying the
VM should you want to continue to use this image.

```bash
terraform state rm aws_ami_from_instance.transparent-security-env-build
Removed aws_ami_from_instance.transparent-security-env-build
Successfully removed 1 resource instance(s).
```

### Clean up the VM used to create the AMI

This step will remove everything except the AMI that was used to create the VM
when the call above has been made.

```bash
terraform destroy -auto-approve -var-file="/path/to/my-tofino.tfvars -var-file="(my-tofino-build.tfvars|my-siddhi-maven-build.tfvars)"
```

Sample output:

```bash
.
.
.
aws_key_pair.transparent-security-mini-pk: Destruction complete after 0s
aws_security_group.transparent-security-img-sg: Destruction complete after 0s

Destroy complete! Resources: 5 destroyed.

Process finished with exit code 0
```
