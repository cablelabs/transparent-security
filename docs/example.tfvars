#EC2 credentials
#NOTE-The mininet-ami variable MUST be changed to point to the image created from the CI env-build
access_key = "AKIAIOSFODNN7EXAMPLE"    #Amazon EC2 access key
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"   #Amazon EC2 secret key
mininet-ami = "ami-09263e0c9493510b0"  # MUST be changed to the AMI ID generated from CI env-build
ec2_region = "us-west-2"  #Amazon EC2 region; Optional to change
