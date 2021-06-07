![Status: Experimental](https://img.shields.io/badge/Version-Experimental-green.svg)
[![License: Mulan](https://img.shields.io/badge/license-Mulan-brightgreen.svg)](https://license.coscl.org.cn/MulanPSL)


![Penglai Header](docs/images/penglai_hdr.jpg)



## Introduction

Penglai is a RISC-V TEE system, which is designed to be **secure**, **high-performant**, and **scalable**.
This repo maintains OpenSBI version of Penglai Enclave based on PMP.

**How to use?**

Simply replace the OpenSBI used in your system with opensbi-0.9 in the top directory in the repo.

You can use our SDK and enclave-driver to build your trusted applications, or even write your own SDKs.

## Status and Info

- Status: experimental: it's still experimental version now, please refer our TVM version for more features.
- Hardware requirement: riscv qemu (suggested version: >= 5.2.0) is fine
- Supported software system: This repo contains resources to run OpenEuler with Penglai TEE.
- Real devices: Penglai for Nuclei devices is maintained in [Nuclei SDK](https://github.com/Nuclei-Software/nuclei-linux-sdk/tree/dev_flash_penglai_spmp).

## Case: Running OpenEuler with Penglai

### Requirements

Penglai uses Docker for building and uses submodules to track different componets.
Therefore, the only requirement to build and run penglai-demo is:

- [Docker](https://docs.docker.com): for building/running Penglai
- Git: for downloading the code

### Build OpenEuler Kernel

Follow the instructions in openeuler riscv gitee to compile OpenEuler kernel.

For example, download the OKL-5.10 in current directory, and compile with penglai's docker image:

	docker run --rm -it -v $(pwd):/env ddnirvana/penglai-enclave:v0.5 /bin/bash
	cd /env
	CROSS_COMPILE=riscv64-unknown-linux-gnu- make ARCH=riscv -j8

### Build OpenSBI (with Penglai supports)

	docker run --rm -it -v $(pwd):/env ddnirvana/penglai-enclave:v0.5 /bin/bash
	cd /env/opensbi-0.6
	CROSS_COMPILE=riscv64-unknown-linux-gnu- make O=build-oe/qemu-virt PLATFORM=qemu/virt FW_PAYLOAD=y FW_PAYLOAD_PATH=/env/Image

Note: the /env/Image is the image compiled OpenEuler Kernel Image.

A simpler way:

	./docker_cmd.sh docker
	#In the docker image
	./scripts/build_opensbi.sh

### Run OpenEuler with Penglai Supports

	qemu-system-riscv64 -nographic -machine virt \
	-smp 8 -m 2G \
	-kernel  /home/dd/devlop/penglai/penglai-openeular/opensbi/opensbi-0.6/build-oe/qemu-virt/platform/qemu/virt/firmware/fw_payload.elf  \
	-drive file=openEuler-preview.riscv64.qcow2,format=qcow2,id=hd0 \
	-object rng-random,filename=/dev/urandom,id=rng0 \
	-device virtio-rng-device,rng=rng0 \
	-device virtio-blk-device,drive=hd0  \
	-device virtio-net-device,netdev=usernet \
	-netdev user,id=usernet,hostfwd=tcp::12055-:22 \
	-append 'root=/dev/vda1 rw console=ttyS0 systemd.default_timeout_start_sec=600 selinux=0 highres=off mem=4096M earlycon' \
	-bios none


- The test qemu version is 5.2.0.
- The fw_payload.elf is the opensbi file.
- The openEuler-preview.riscv64.qcow2 is the disk image for OpenEuler.
- To login, username is "root", passwd is "openEuler12#$"

Note: a script, run_openeuler.sh is provided to execute the above command easily


If everything is fine, you will enter a Linux terminal booted by Qemu with Penglai-installed.

**Insmod the enclave-driver**

`insmod penglai.ko`

And the, you can run a demo, e.g., a prime enclave, using

`./host  prime`

Here, the  `host` is an enclave invoker, which will start an enclave (name from input).

## License Details

Mulan Permissive Software License，Version 1 (Mulan PSL v1)

## Code Structures

- opensbi-0.9: The Penglai-equipped OpenSBI, version 0.9
- openeuler-kernel: OpenEuler Kernel
- riscv-qemu: The modified qemu (4.1) to support sPMP (you can also use the standard qemu)
- scripts: some scripts to build/run Penglai demo

## Code Contributions

Please fell free to post your concerns, ideas, code or anything others to issues.

## Wiki

Please refer the wiki for more details

## Cite

To cite Penglai, please consider using the following bibtex:
```
@inproceedings{feng2021penglai,
  title={Scalable Memory Protection in the PENGLAI Enclave},
  author={Erhu, Feng and Xu, Lu and Dong, Du and Bicheng, Yang and Xueqiang, Jiang and Yubin, Xia and Binyu, Zang and Haibo, Chen},
  booktitle={15th $\{$USENIX$\}$ Symposium on Operating Systems Design and Implementation ($\{$OSDI$\}$ 21)},
  year={2021}
}
```

## Acknowledgements

The design of Penglai was inspired by Sanctum, Keystone and HexFive, thanks to their great work!

