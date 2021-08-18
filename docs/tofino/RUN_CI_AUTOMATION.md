# transparent-security automation for the tofino-model

The scripts outlined here can be executed within a CI server or locally during
development

### Getting started
Below are the variables used by the tofino CI automation scripts.

| Variable         | Description                                                                                                                               | Type   | Example                                                 |
|------------------|-------------------------------------------------------------------------------------------------------------------------------------------|--------|---------------------------------------------------------|
| build_id         | This value must be unique to ensure multiple jobs  can be run simultaneously from multiple hosts            | string | build_id = "example-1"                                  |
| access_key       | Amazon EC2 access key                                                                                       | string | access_key = "AKIAIOSFODNN7EXAMPLE"                     |
| secret_key       | Amazon EC2 secret key                                                                                       | string | secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" |
| ec2_region       | Amazon EC2 region                                                                                           | string | ec2_region = "us-west-2" (default)                      |
| public_key_file  | Used to inject into the VM for SSH access with the user'ubuntu' (defaults to ~/.ssh/id_rsa.pub)             | string | public_key_file = "~/.ssh/id_rsa.pub" (default)         |
| private_key_file | Used to access the VM via SSH with the user 'ubuntu' (defaults to ~/.ssh/id_rsa)                            | string | private_key_file = "~/.ssh/id_rsa" (default)            |
| bf_sde_version   | When this value will be used to obtaining the BF-SDE version                                                | string | bf_sde_version = "9.2.0" (default)                      |

### Run terraform to launch the cluster on AWS.

##### Configure
Please see the following example Terraform Variable files to create the files
to hold the Terraform program arguments via the  --var-file command line option
in the "Execute" section below.

- [my-automation-base.tfvars template](../terraform/automation-base.example.tfvars)
- [my-tofino-int.tfvars template](../terraform/tofino-int.example.tfvars)


```bash
cd transparent-security/automation/p4/tofino
terraform init
terraform apply -auto-approve -var-file="my-automation-base.tfvars -var-file="my-tofino-build.tfvars" -var scenario_name=(aggregate|core|lab_trial)"
```

### SSH into orchestrator/controller machine

Use the SSH keys indicated in the variable file to login to the VM.
```bash
# from transparent-security/automation/p4/tofino directory
ssh -i { key file } ubuntu@$(terraform output ip)
```

### What is deployed
Controller/Orchestrator node with outside access

#### scenario_name=lab_trial
* 1 orchestrator/controller node (Performs deployment and runs SDN controller)
* 4 network nodes (Standard Linux VMs)
* 2 Tofino switches (Linux VMs with the BF-SDE running the P4 programs)

###### Switches (with bf-sde-{version} and transparent-security installed into python runtime)
- core (running core.p4)
- aggregate (running aggregate.p4)

###### Nodes (vanilla linux with transparent-security installed into python runtime)
- inet (to core)
- ae (to core)
- host1 (to aggregate)
- host2 (to core)

#### scenario_name=aggregate|core
* 1 orchestrator/controller node
* 2 network nodes
* 1 Tofino switch

###### Switches (with bf-sde-{version} and transparent-security installed into python runtime)
- runs (aggregate|core).p4

###### Nodes (vanilla linux with transparent-security installed into python runtime)
- host1 (southbound server node)
- host2 (northbound server node)

#### Accessing the switches and nodes from orchestrator
From the orchestrator node, you can gain access to all other nodes and switch VMs
by name with user 'ubuntu':

```bash
ssh {switch_name | node_name}
```

### Cleanup the simulation environment

This will remove the VM and other artifacts created when it was deployed.

```bash
# from transparent-security/automation/p4/tofino directory
terraform destroy -auto-approve -var-file="my-automation-base.tfvars -var-file="my-tofino-build.tfvars" -var scenario_name="destroy"
```
