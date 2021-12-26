## Release notes


---
v0.2 (2021/12/26)

This release contains the following improvements compared with prior one:

- Attestation supported
- Add user-defined ocalls to allow host implements more functionalities for enclaves
- Supported shared untrusted memory
- Other imrpvoements, e.g., reading the SM_BASE/SM_SIZE from opensbi's linker symbols, enabling float in the monitor

This release also supports more devices, e.g., Nuclei NX600, Starfive Starlight boards, as well as more  applications, e.g., a tensorflow demo.

This release is supposed to be the last release using OpenSBI v0.9, and we will go forward to OpenSBI v1.0 in the next release.

Many thanks to everyone who has contributed to this release.


---
v0.1 (2021/7/15)

This is the first release of Penglai-PMP (the isolation mechanism is PMP or sPMP) implementing v2 of the Penglai SBI extension API.
The release contains basic TEE functionalities on RISC-V, including enclave create, run, resume, stop, destroy.
This release focuses on 64bit RISC-V systems (32bit not tested in this version).
