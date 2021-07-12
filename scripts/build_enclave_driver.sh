#!/bin/bash
## Author: Dong Du
## This scripts should run in the Penglai-Build container
## Note: You should build the kernel first (so the enclave driver can find necessary files)

## To build enclave-driver
cd /home/penglai/penglai-enclave/penglai-enclave-driver
CROSS_COMPILE=riscv64-unknown-linux-gnu- make
