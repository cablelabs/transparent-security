# transparent-security Mininet integration setup on AWS
Readme for information on building a transparent-security environment

### Host Requirements

- Python 2.7 is installed
- The python-pip package has been installed
- The Python ansible >=2.7.5 package has been installed

### Install terraform

Download and install your binary for your platform from  https://www.terraform.io/downloads.html

### Setup and execute

This Terraform script has been designed to run and execute unit tests for P4
programs on mininet:

1. build_id: this value must be unique to ensure multiple jobs can be run
simultaneously from multiple hosts

````
git clone https://github.com/cablelabs/transparent-security
git clone https://github.com/cablelabs/snaps-config
cd transparent-security/ci/p4/mininet
terraform init
terraform apply -var-file=~/snaps-config/aws/snaps-ci.tfvars \
-auto-approve \
-var 'build_id={some unique value}'\
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
-auto-approve -var\
-var 'build_id={some unique value}'\
````

## Running Mininet Simulation
To run the Mininet Simluation you need to have four (4) shells open to the EC2 instance. 
````
# from transparent-security/ci/p4/mininet directory
ssh -i ubuntu@$(terraform output ip)
````

### Mininet 

````bash
# from transparent-security/mininet-start
make stop clean run_mininet_daemon 
````

It should finish with 


````bash

==============================================================
Welcome to the BMV2 Mininet CLI!
==============================================================
Your P4 program is installed into the BMV2 software switch
and your initial configuration is loaded. You can interact
with the network using the mininet CLI below.

To view a switch log, run this command from your host OS:
  tail -f /home/ubuntu/transparent-security/mininet-start/logs/<switchname>.log

To view the switch output pcap, check the pcap files in /home/ubuntu/transparent-security/mininet-start/pcaps:
 for example run:  sudo tcpdump -xxx -r s1-eth1.pcap

mininet> 
````
Note: 
 - stop -> stops any switch instances still running
 - clean -> removes logs, builds, artifacts, etc... 
 - run_mininet_daemon -> builds/runs mininet with the nominal and attack daemons running

*If you don't want the daemons to run automatically, use:*

 `make stop clean run`

### SDN Controller

```bash
$ sudo --help #to see the options
#typical
$ sudo ../apps/sdn_controller.py -m true -l debug --logfile=./logs/sdn_controller.log
```
AE

```bash
$ sudo --help #to see options
#typical
$ sudo ../apps/start_ae.py -i eth0
```

