#Unique ID for this build
build_id = "changeme-1"

# EC2 credentials
# NOTE-The mininet-ami variable MUST be changed to point to the image created from the CI env-build
# Amazon EC2 access key
access_key = "AKIAIOSFODNN7EXAMPLE"

# Amazon EC2 secret key
secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Amazon EC2 region; Optional to change
ec2_region = "us-west-2"

# Used to inject into the VM for SSH access with the user'ubuntu' (defaults to ~/.ssh/id_rsa.pub)
# public_key_file = "~/.ssh/id_rsa.pub"

# Used to access the VM via SSH with the user 'ubuntu' (defaults to ~/.ssh/id_rsa)
# private_key_file = "~/.ssh/id_rsa"

# The type of environemnt being used
# Only used for creating the environment
# env_type = "mininet"

# MUST be changed to the AMI ID generated from CI env-build
# Only used for running simulator
# mininet_ami = "ami-060d055b5ca40de8c"
