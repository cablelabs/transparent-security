#Unique ID for this build
build_id = "test-1"

# The type of environemnt being used
env_type = "mininet"

# EC2 credentials
# NOTE-The mininet-ami variable MUST be changed to point to the image created from the CI env-build
# Amazon EC2 access key
access_key = "AKIAIOSFODNN7EXAMPLE"

# Amazon EC2 secret key
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# MUST be changed to the AMI ID generated from CI env-build
mininet-ami = "ami-09263e0c9493510b0"

# Amazon EC2 region; Optional to change
ec2_region = "us-west-2"

# When 'True', the mininet host daemons will be started else not (Default 'True')
run_daemons = "True"
