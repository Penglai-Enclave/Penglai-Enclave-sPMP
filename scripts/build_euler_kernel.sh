#!/bin/bash
## Author: Dong Du
## This scripts should run in the Penglai-Build container

## To create openEuler kernel config
cd /home/penglai/penglai-enclave/openeuler-kernel
cat openEuler_riscv64_defconfig >> arch/riscv/configs/defconfig
make -s mrproper
CROSS_COMPILE=riscv64-unknown-linux-gnu- make ARCH=riscv defconfig


## To build kernel and enclave-driver
cd /home/penglai/penglai-enclave/openeuler-kernel
CROSS_COMPILE=riscv64-unknown-linux-gnu- make ARCH=riscv -j8
cd /home/penglai/penglai-enclave/penglai-enclave-driver
CROSS_COMPILE=riscv64-unknown-linux-gnu- make
