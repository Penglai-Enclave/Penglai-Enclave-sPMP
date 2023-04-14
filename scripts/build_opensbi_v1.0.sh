#!/bin/bash
cd /home/penglai/penglai-enclave/opensbi-1.0
mkdir -p build-oe/qemu-virt
CROSS_COMPILE=riscv64-unknown-linux-gnu- make O=build-oe/qemu-virt PLATFORM=generic FW_PAYLOAD=y FW_PAYLOAD_PATH=/home/penglai/penglai-enclave/Image
#cp build-oe/qemu-virt/platform/qemu/virt/firmware/fw_payload.elf build-oe/qemu-virt/boot/fw_payload_oe_qemuvirt.elf
