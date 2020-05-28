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
| env_type         | The type of environment being built (only used for creating the environment)                                                              | string | env_type = "tofino"                                    |

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

Variable file must also contain the following lines as the default is tied to
a CableLabs AWS account:
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
terraform apply -auto-approve -var-file="/path/to/my-tofino.tfvars -var bf_sde_s3_bucket={bucket name}"
```

### SSH into orchestrator/controller machine

Use the SSH keys indicated in the variable file to login to the VM.
```bash
# from transparent-security/automation/p4/tofino directory
ssh -i { key file } ubuntu@$(terraform output ip)
```

### What is deployed
Controller/Orchestrator node with outside access
9 network nodes
5 Tofino switches

####
From the orchestrator node, you can gain access to all other nodes and switch VMs
by name with user 'ubuntu':
##### Switches (with bf-sde-{version} and transparent-security installed into python runtime)
- core (running core.p4)
- aggregate (running aggregate.p4)
- gateway1 (running gateway.p4)
- gateway2 (running gateway.p4)
- gateway3 (running gateway.p4)

##### Nodes (vanilla linux with transparent-security installed into python runtime)
- inet (to core)
- analytics_engine (to core)
- Camera1 (to gateway1)
- Game1 (to gateway1)
- NAS1 (to gateway1)
- Camera2 (to gateway2)
- Game2 (to gateway2)
- Camera3 (to gateway3)
- Game3 (to gateway3)

```bash
ssh core
```

### Cleanup the simulation environment

This will remove the VM and other artifacts created when it was deployed.

```bash
# from transparent-security/automation/p4/tofino directory
terraform destroy -auto-approve -var-file="/path/to/my-tofino.tfvars"
```
