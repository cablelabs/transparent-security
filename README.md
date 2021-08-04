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

## The directories
- automation - contains Terraform scripts for CI and testing on AWS
- bin - miscellaneous scripts mostly used by scripts in automation
- conf - miscellaneous environment configurations
- docs - miscellaneous MD files
- p4 - The P4 source code
- playbooks - The Ansible Playbooks used by automation
- snaps-hcp - Documentation on snaps-hcp which is no longer being used
- tests - the Python unit test directory
- trans_sec - the project's top-level Python package