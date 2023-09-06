[![build](https://github.com/Penglai-Enclave/Penglai-Enclave-sPMP/actions/workflows/build.yml/badge.svg)](https://github.com/Penglai-Enclave/Penglai-Enclave-sPMP/actions/workflows/build.yml)
![Status: Experimental](https://img.shields.io/badge/Version-Experimental-green.svg)
[![License: Mulan](https://img.shields.io/badge/license-Mulan-brightgreen.svg)](https://license.coscl.org.cn/MulanPSL)


![Penglai Header](docs/images/penglai_hdr.jpg)



## Introduction

Penglai is a RISC-V TEE system, which is designed to be **secure**, **high-performant**, and **scalable**.
This repo maintains OpenSBI version of Penglai Enclave based on PMP.

**How to use?**

Simply replace the OpenSBI used in your system with opensbi-1.2 in the top directory in the repo.

You can use our SDK and enclave-driver to build your trusted applications, or even write your own SDKs.

## Status and Info

- Status: experimental: it's still experimental version now, please refer our TVM version for more features.
- Hardware requirement: riscv qemu (suggested version: >= 5.2.0) is fine
- Supported software system: This repo contains resources to run openEuler with Penglai TEE.
- Real devices: Penglai for Nuclei devices is maintained in [Nuclei Linux SDK](https://github.com/Nuclei-Software/nuclei-linux-sdk/tree/dev_flash_penglai_spmp).

You can turn to BBL-version by switching to the master branch.

You can refer our [Penglai-TVM](https://github.com/Penglai-Enclave/Penglai-Enclave-TVM) for more advanced features, including inter-enclave communication, secure storage, shadow fork, and others.

## Case: Running openEuler with Penglai

### Requirements

Penglai uses Docker for building and uses submodules to track different componets.
Therefore, the only requirement to build and run penglai-demo is:

- [Docker](https://docs.docker.com): for building/running Penglai
- Git: for downloading the code
- Qemu for RISC-V (RV64): suggested version >= 5.2.0. You can download the qemu [here](https://www.qemu.org/) and follow the [instructions](https://wiki.qemu.org/Documentation/Platforms/RISCV) to build and install qemu.

### Build uboot
U-boot 23.04 Download:https://github.com/u-boot/u-boot/archive/refs/tags/v2023.04.tar.gz
Execute the following command to compile and get uboot.bin
```shell
make qemu_riscv64_smode_defconfig
make ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- -j$(nproc)
```

### Build OPENSBI
Execute the following commands to compile fw_payload.bin (note that the local path should be changed as needed).
```shell
cd ../Penglai-Enclave-sPMP/opensbi-1.2
rm -rf build-oe/qemu-virt
mkdir -p build-oe/qemu-virt
CROSS_COMPILE=riscv64-unknown-linux-gnu- make O=build-oe/qemu-virt PLATFORM=generic FW_PAYLOAD=y FW_PAYLOAD_PATH=../Penglai-Enclave-sPMP/u-boot.bin -j$(nproc)
```
### Run openEuler with Penglai Supports

You should download the disk image of openEuler (i.e., openEuler-23.03-V1-base-qemu-preview.qcow2) from [openEuler-23.03](https://mirror.iscas.ac.cn/openeuler-sig-riscv/openEuler-RISC-V/preview/openEuler-23.03-V1-riscv64/QEMU/),download and unzip openEuler-23.03-V1-base-qemu-preview.qcow2.zst.
```shell
qemu-system-riscv64 -nographic -machine virt \
        -smp 4 -m 2G \
        -bios  ./fw_payload.bin  \
        -drive file=openEuler-23.03-V1-base-qemu-preview.qcow2,format=qcow2,id=hd0 \
        -object rng-random,filename=/dev/urandom,id=rng0 \
        -device virtio-rng-device,rng=rng0 \
        -device virtio-blk-device,drive=hd0  \
        -device virtio-net-device,netdev=usernet \
        -netdev user,id=usernet,hostfwd=tcp::12055-:22 \
        -device qemu-xhci -usb -device usb-kbd -device usb-tablet
```

- The test qemu version is 8.0.
- To login, username is "root", passwd is "openEuler12#$"

### Compiling the kernel module in the qemu virtual machine

After the above startup is complete get the source code in the VM and execute compile kernel moudle:
```shell
sudo dnf install -y kernel-devel kernel-source
```
The kernel source code will be downloaded locally,the path is `/usr/lib/modules/6.1.19-2.oe2303.riscv64`.

Copy penglai-enclave-driver to the root/ directory of the oe VM.
Go to the penglai-enclave-driver directory and modify the original kernel source path openeuler-kernel in the Makefile to `/usr/lib/modules/6.1.19-2.oe2303.riscv64/build/`.
Compile and install the kernel module:
```shell
cd penglai-enclave-driver
vim Makefile #modify source path 
make -j$(nproc)
insmod penglai.ko
```

Following the commnads to build user-level sdk and demos:

	# Fetch the sdk submodule
	git submodule update --init --recursive

	./docker_cmd.sh docker
	# In the docker image
	cd sdk
	PENGLAI_SDK=$(pwd) make -j8


If everything is fine, you will enter a Linux terminal booted by Qemu with Penglai-installed.

**Copy files to openEuler Qemu**

You can copy any files to the VM using *scp*.

For example, to run the following demo, you should:

	scp -P 12055 sdk/demo/host/host root@localhost:~/
	scp -P 12055 sdk/demo/prime/prime root@localhost:~/

The passwd is "openEuler12#$"

And the, you can run a demo, e.g., a prime enclave, using

`./host  prime`

Here, the  `host` is an enclave invoker, which will start an enclave (name from input).

## License Details

Mulan Permissive Software License，Version 1 (Mulan PSL v1)

## Code Structures

- opensbi-1.2: The Penglai-equipped OpenSBI, version 1.2
- openeuler-kernel: openEuler Kernel
- riscv-qemu: Tstandard qemu (8.0)
- scripts: some scripts to build/run Penglai demo

## Code Contributions

Please fell free to post your concerns, ideas, code or anything others to issues.

## Document and Tutorial

Please refer our readthedocs page for [documents](https://penglai-doc.readthedocs.io/).

## Cite

To cite Penglai, please consider using the following bibtex:
```
@inproceedings {273705,
	author = {Erhu Feng and Xu Lu and Dong Du and Bicheng Yang and Xueqiang Jiang and Yubin Xia and Binyu Zang and Haibo Chen},
	title = {Scalable Memory Protection in the {PENGLAI} Enclave},
	booktitle = {15th {USENIX} Symposium on Operating Systems Design and Implementation ({OSDI} 21)},
	year = {2021},
	isbn = {978-1-939133-22-9},
	pages = {275--294},
	url = {https://www.usenix.org/conference/osdi21/presentation/feng},
	publisher = {{USENIX} Association},
	month = jul,
}
```
## Collaborators

We thank all of our collaborators (companies, organizations, and communities).

[<img alt="Huawei" src="./docs/collaborator-logos/huawei.png" width="146">](https://www.huawei.com/) |[<img alt="nuclei" src="./docs/collaborator-logos/nuclei.png" width="146">](https://www.nucleisys.com/) |[<img alt="StarFive" src="./docs/collaborator-logos/starfive.jpeg" width="146">](https://starfivetech.com/) |[<img alt="ISCAS" src="./docs/collaborator-logos/ISCAS.svg" width="146">](http://www.is.cas.cn/) |
:---: |:---: |:---: |:---: |
[Huawei (华为)](https://www.huawei.com/) |[Nuclei (芯来科技)](https://www.nucleisys.com/) |[StarFive (赛昉科技)](https://starfivetech.com/) |[ISCAS(中科院软件所)](http://www.is.cas.cn/) |

[<img alt="openEuler" src="./docs/collaborator-logos/openeuler.png" width="146">](https://openeuler.org/) |[<img alt="OpenHarmony" src="./docs/collaborator-logos/OpenHarmony.svg" width="146">](https://www.openharmony.cn/) |[<img alt="secGear" src="./docs/collaborator-logos/secGear.png" width="146">](https://gitee.com/openeuler/secGear) |
:---: |:---: |:---: |
[openEuler community](https://openeuler.org/) |[OpenHarmony community](https://www.openharmony.cn/) |[secGear framework](https://gitee.com/openeuler/secGear)|

## Acknowledgements

The design of Penglai was inspired by Sanctum, Keystone and HexFive, thanks to their great work!

