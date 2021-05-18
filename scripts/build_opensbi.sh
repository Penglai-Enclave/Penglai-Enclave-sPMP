#!/bin/bash
cd /home/penglai/penglai-enclave/opensbi-0.6
CROSS_COMPILE=riscv64-unknown-linux-gnu- make O=build-oe/qemu-virt PLATFORM=qemu/virt FW_PAYLOAD=y FW_PAYLOAD_PATH=/home/penglai/penglai-enclave/Image
