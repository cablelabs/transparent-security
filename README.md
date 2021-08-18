# Transparent Security

Transparent Security is a solution for identify the source devices of a DDoS attack and mitigates the attack in the customer premises or the access network. This solution leverages a P4 based programmable data plane for add in-band network telemetry (INT) for device identification and in-band mitigation.

> Note: This is reference implementation for a minimal viable prototype.

For more information see the 
[blog and white paper](https://www.cablelabs.com/vaccinate-your-network-to-prevent-the-spread-of-ddos-attacks).

## Getting started

```
$ git clone https://github.com/cablelabs/transparent-security
```

If you're new to git and GitHub, be sure to check out the [Pro
Git](https://git-scm.com/book/en/v2) book. [GitHub
Help](https://help.github.com/) is also outstanding.

Or you can stay right here in your web browser on GitHub.

## Contributing

Transparent Security was originally built by [CableLabs](http://cablelabs.com/),
but we could use your help! Check out our
[contributing guidelines](CONTRIBUTING.md) to get started.

## Other important stuff

We use an [Apache 2.0 License](LICENSE) for Transparent Security.

Questions? Just send us an email at
[transparent-security@cablelabs.com](mailto:transparent-security@cablelabs.com) or [open an issue](https://github.com/cablelabs/transparent-security/issues).

## The docs
These directories contain other documentation 
- [Analytic Engine](./docs/ae) - [How to setup the AE](./docs/ae/SIDDHI_AE_SETUP.md)
  - [kubernetes](./docs/ae/kubernetes) - directory containing sample CRDs to deploy the TPS AE on Kubernetes
- [Build automation AMIs](./docs/env_build) - [Creating the required EC2 Images](./docs/env_build/CREATE_AUTOMATION_IMAGES.md)
- [P4 INT](./docs/int_header) - [Description of the P4 INT header added to packets and associated Wireshark plugin](./docs/int_header/README.md)
- [Telemetry Report](./docs/telemetry_report) - [Description of the Telemetry Report UDP Packet](./docs/telemetry_report/telemetry_report.md)
- [Terraform Example Variable File](./docs/terraform) - Example "tfvars" files for configuring a Terraform run
- [P4 Automation](./docs/tofino) - [Instructions on how to execute the P4 automation scripts](./docs/tofino/RUN_CI_AUTOMATION.md)

## The directories
- [automation](automation) - contains Terraform scripts for CI and testing on AWS
- [bin](bin) - miscellaneous scripts mostly used by scripts in automation
- [conf](conf) - miscellaneous environment configurations
- [docs](docs) - miscellaneous MD files
- [p4](p4) - The P4 source code
- [playbooks](playbooks) - The Ansible Playbooks used by automation
- [tests](tests) - the Python unit test directory
- [trans_sec](trans_sec) - the project's top-level Python package
