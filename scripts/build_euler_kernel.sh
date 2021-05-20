#!/bin/bash
cd /home/penglai/penglai-enclave/openeuler-kernel
CROSS_COMPILE=riscv64-unknown-linux-gnu- make ARCH=riscv -j8
cd /home/penglai/penglai-enclave/penglai-enclave-driver
CROSS_COMPILE=riscv64-unknown-linux-gnu- make
