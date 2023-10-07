[![build](https://github.com/Penglai-Enclave/Penglai-Enclave-sPMP/actions/workflows/build.yml/badge.svg)](https://github.com/Penglai-Enclave/Penglai-Enclave-sPMP/actions/workflows/build.yml)
![Status: Experimental](https://img.shields.io/badge/Version-Experimental-green.svg)
[![License: Mulan](https://img.shields.io/badge/license-Mulan-brightgreen.svg)](https://license.coscl.org.cn/MulanPSL)


![Penglai Header](docs/images/penglai_hdr.jpg)



## Introduction

Penglai is a RISC-V TEE system, which is designed to be **secure**, **high-performant**, and **scalable**. This repo maintains OpenSBI version of Penglai Enclave based on PMP.

**How to use?**

Simply replace the OpenSBI used in your system with opensbi-0.9/1.0/1.2 in the top directory in the repo.

You can use our SDK and enclave-driver to build your trusted applications, or even write your own SDKs.

## Status and Info

- Status: experimental: it's still experimental version now, please refer our TVM version for more features.
- Hardware requirement:for openEuler version $\le$ 20.03,  riscv qemu version: $\geq$ 5.2.0 is fine;for openEuler version $\ge$ 22, qemu version:$\geq$ 8.0 is suggested.
- Supported software system: This repo contains resources to run openEuler with Penglai TEE.
- Real devices: Penglai for Nuclei devices is maintained in [Nuclei Linux SDK](https://github.com/Nuclei-Software/nuclei-linux-sdk/tree/dev_flash_penglai_spmp).

You can turn to BBL-version by switching to the master branch.

You can refer our [Penglai-TVM](https://github.com/Penglai-Enclave/Penglai-Enclave-TVM) for more advanced features, including inter-enclave communication, secure storage, shadow fork, and others.

## Case: Running openEuler with Penglai

### Requirements

Penglai uses Docker for building and uses submodules to track different componets. Therefore, the only requirement to build and run penglai-demo is:

- [Docker](https://docs.docker.com): for building/running Penglai
- Git: for downloading the code
- Qemu for RISC-V (RV64): suggested version >= 8.0. You can download the qemu [here](https://www.qemu.org/) and follow the [instructions](https://wiki.qemu.org/Documentation/Platforms/RISCV) to build and install qemu.

### Build uboot

**For openEuler version $\lt$ 23:**

There is no need to compile uboot.

**For openEuler version $\ge$ 23:**

Follow the instructions in openeuler riscv gitee to compile uboot for OE-23.X.

```
# Fetch the uboot submodule
git submodule update --init --recursive
cd ./u-boot
make qemu-riscv64_defconfig
make ARCH=riscv CROSS_COMPILE=riscv64-unknown-linux-gnu- -j$(nproc)
```

### Build openEuler Kernel

**For openEuler version $\lt$ 23:**

Follow the instructions in openeuler riscv gitee to compile openEuler kernel.

For example, download the OKL-5.10 in current directory, and compile with penglai's docker image:

	docker run -v $(pwd):/home/penglai/penglai-enclave -w /home/penglai/penglai-enclave --rm -it ddnirvana/penglai-enclave:v0.5 bash
	# In the docker image
	./scripts/build_euler_kernel.sh

**For openEuler version $\ge$ 23:**

For oe versions greater than 23, you can access the source code after [Run openEuler with Penglai Supports](#run-openeuler-with-penglai-supports) and don't need to compile the image like in the previous step for  version $\lt$ 23.

### Build OpenSBI (with Penglai supports)
**For openEuler version $\lt$ 23:**

	copy openeuler-kernel/arch/riscv/boot/Image .
	docker run -v $(pwd):/home/penglai/penglai-enclave -w /home/penglai/penglai-enclave --rm -it ddnirvana/penglai-enclave:v0.5 bash
	# In the docker image
	cd /home/penglai/penglai-enclave/opensbi-0.9
	mkdir -p build-oe/qemu-virt
	CROSS_COMPILE=riscv64-unknown-linux-gnu- make O=build-oe/qemu-virt PLATFORM=generic FW_PAYLOAD=y FW_PAYLOAD_PATH=/home/penglai/penglai-enclave/Image

Note: the /home/penglai/penglai-enclave/Image is the image compiled openEuler Kernel Image.

**For openEuler version $\ge$ 23:**

```
copy ../Penglai-Enclave-sPMP/u-boot/u-boot.bin
docker run -v $(pwd):/home/penglai/penglai-enclave -w /home/penglai/penglai-enclave --rm -it ddnirvana/penglai-enclave:v0.5 bash
cd ../Penglai-Enclave-sPMP/opensbi-1.2
rm -rf build-oe/qemu-virt
mkdir -p build-oe/qemu-virt
CROSS_COMPILE=riscv64-unknown-linux-gnu- make O=build-oe/qemu-virt PLATFORM=generic FW_PAYLOAD=y FW_PAYLOAD_PATH=../Penglai-Enclave-sPMP/u-boot.bin -j$(nproc)
```

A simpler way:

```
./docker_cmd.sh docker
#In the docker image，build opensbi 1.2 for OE20.03
#./scripts/build_opensbi.sh -v [opensbi version] -k [openEuler version]
./scripts/build_opensbi.sh -v 1.2 -k 2003
```

**Note**: if you use the simpler way, please **copy** your latest kernel *Image* file to the root dir of the repo.

### Build Penglai SDK

**For openEuler version $\lt$ 23:**

When openeuler version is less than 23,following the commands to build enclave driver:

	./docker_cmd.sh docker
	# In the docker image
	./scripts/build_enclave_driver.sh

It will generate penglai.ko in the penglai-enclave-driver dir.

**For openEuler version $\ge$ 23:**

When openEuler version is >= 23,  you need to start openEuler in qemu as the next step [Run openEuler with Penglai Supports](#run-openeuler-with-penglai-supports) finished before compiling penglai-driver.



When penglai.ko is completed,following the commnads to build user-level sdk and demos:

	#In host, fetch the sdk submodule
	git submodule update --init --recursive
	
	./docker_cmd.sh docker
	# In the docker image
	cd sdk
	PENGLAI_SDK=$(pwd) make -j8

### Run openEuler with Penglai Supports

You should download the disk image of openEuler (i.e., openEuler-preview.riscv64.qcow2) and raname image file to openEuler-xxxx-qemu-riscv64.qcow2.

You can download OE 2303 from [openEuler-23.03-V1-riscv64](https://mirror.iscas.ac.cn/openeuler-sig-riscv/openEuler-RISC-V/preview/openEuler-23.03-V1-riscv64/QEMU/)(i.e., openEuler-23.03-V1-base-qemu-preview.qcow2）or download openEuler 20.03 from [here](http://pan.sjtu.edu.cn/web/share/4440d1d40d859f141d9e6cf18b89bb4d).

```
wget https://mirror.iscas.ac.cn/openeuler-sig-riscv/openEuler-RISC-V/preview/openEuler-23.03-V1-riscv64/QEMU/openEuler-23.03-V1-base-qemu-preview.qcow2.zst
unzstd openEuler-23.03-V1-base-qemu-preview.qcow2.zst
mv openEuler-23.03-V1-base-qemu-preview.qcow2 openEuler-2303-qemu-riscv64.qcow2
```

**For openEuler version $\lt$ 23:**

Run VM in QEMU：

	# For openEuler version is 20.03
	qemu-system-riscv64 -nographic -machine virt \
	-smp 4 -m 2G \
	-kernel  ./opensbi-0.9/build-oe/qemu-virt/platform/generic/firmware/fw_payload.elf  \
	-drive file=openEuler-preview.riscv64.qcow2,format=qcow2,id=hd0 \
	-object rng-random,filename=/dev/urandom,id=rng0 \
	-device virtio-rng-device,rng=rng0 \
	-device virtio-blk-device,drive=hd0  \
	-device virtio-net-device,netdev=usernet \
	-netdev user,id=usernet,hostfwd=tcp::12055-:22 \
	-append 'root=/dev/vda1 rw console=ttyS0 systemd.default_timeout_start_sec=600 selinux=0 highres=off mem=4096M earlycon' \
	-bios none


- The test qemu version is 5.2.0 or 8.0.0.
- The fw_payload.elf is the opensbi file.
- The openEuler-preview.riscv64.qcow2 is the disk image for openEuler (You can download from https://repo.openeuler.org/openEuler-preview/RISC-V/Image/).
- To login, username is "root", passwd is "openEuler12#$"

Note: a script, run_openeuler.sh is provided to execute the above command easily

```
./run_openeuler.sh -k [openEuler version] -o [opensbi version]
#when openEuler version less than 23,eg 2003
./run_openeuler.sh -k 2003 -o 1.2
#when openEuler version is greater than or equal 23,eg 2303
./run_openeuler.sh -k 2303 -o 1.2
```

If everything is fine, you will enter a Linux terminal booted by Qemu with Penglai-installed.

**For openEuler version $\ge$ 23:**

For openEuler version greater than 23, get the source code in the qemu VM and execute compile kernel moudle with penglai-driver.

Copy penglai-enclave-driver to the root/ directory of the oe VM:

```
#in host
scp -P 12055 penglai-enclave-driver root@localhost:~/
```

Execute the following commands and the kernel source code will be downloaded locally, the path is `/usr/lib/modules/6.1.19-2.oe2303.riscv64`.

```
#in VM
cd ~/
sudo dnf install -y kernel-devel kernel-source
```

Go into the penglai-enclave-driver directory and modify the original kernel source path openeuler-kernel in the Makefile from `../openeuler-kernel/`to `/usr/lib/modules/6.1.19-2.oe2303.riscv64/build/`.

Compile and install the kernel module:

```
cd ~/penglai-enclave-driver
vim Makefile #modify source path 
make -j$(nproc)
insmod penglai.ko
```

### RUN demo

**Copy files to openEuler Qemu**

You can copy any files to the VM using *scp*.

For example, to run the following demo, you should:

	scp -P 12055 penglai-enclave-driver/penglai.ko root@localhost:~/
	scp -P 12055 sdk/demo/host/host root@localhost:~/
	scp -P 12055 sdk/demo/prime/prime root@localhost:~/

The passwd is "openEuler12#$"

**Insmod the enclave-driver**

If you already installed in the previous step, you don't need to repeat it

```
insmod penglai.ko
```

And the, you can run a demo, e.g., a prime enclave, using

```
./host  prime
```

Here, the  `host` is an enclave invoker, which will start an enclave (name from input).

## License Details

Mulan Permissive Software License，Version 1 (Mulan PSL v1)

## Code Structures

- opensbi-0.9: The Penglai-equipped OpenSBI, version 0.9
- opensbi-1.0: The Penglai-equipped OpenSBI, version 1.0
- opensbi-1.2: The Penglai-equipped OpenSBI, version 1.2
- openeuler-kernel: openEuler Kernel
- riscv-qemu: The modified qemu (4.1) to support sPMP (you can also use the standard qemu)
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

| [<img alt="Huawei" src="./docs/collaborator-logos/huawei.png" width="146">](https://www.huawei.com/) | [<img alt="nuclei" src="./docs/collaborator-logos/nuclei.png" width="146">](https://www.nucleisys.com/) | [<img alt="StarFive" src="./docs/collaborator-logos/starfive.jpeg" width="146">](https://starfivetech.com/) | [<img alt="ISCAS" src="./docs/collaborator-logos/ISCAS.svg" width="146">](http://www.is.cas.cn/) |
| :----------------------------------------------------------: | :----------------------------------------------------------: | :----------------------------------------------------------: | :----------------------------------------------------------: |
|           [Huawei (华为)](https://www.huawei.com/)           |       [Nuclei (芯来科技)](https://www.nucleisys.com/)        |       [StarFive (赛昉科技)](https://starfivetech.com/)       |         [ISCAS(中科院软件所)](http://www.is.cas.cn/)         |

| [<img alt="openEuler" src="./docs/collaborator-logos/openeuler.png" width="146">](https://openeuler.org/) | [<img alt="OpenHarmony" src="./docs/collaborator-logos/OpenHarmony.svg" width="146">](https://www.openharmony.cn/) | [<img alt="secGear" src="./docs/collaborator-logos/secGear.png" width="146">](https://gitee.com/openeuler/secGear) |
| :----------------------------------------------------------: | :----------------------------------------------------------: | :----------------------------------------------------------: |
|        [openEuler community](https://openeuler.org/)         |     [OpenHarmony community](https://www.openharmony.cn/)     |   [secGear framework](https://gitee.com/openeuler/secGear)   |

## Acknowledgements

The design of Penglai was inspired by Sanctum, Keystone and HexFive, thanks to their great work!