#!/bin/bash
# cd /home/penglai/penglai-enclave/opensbi-1.2
cd /home/zhaoxi/ipads/Penglai-Enclave-sPMP/opensbi-1.2
rm -rf build-oe/qemu-virt
mkdir -p build-oe/qemu-virt
# CROSS_COMPILE=riscv64-unknown-linux-gnu- make O=build-oe/qemu-virt PLATFORM=generic FW_PAYLOAD=y FW_PAYLOAD_PATH=/home/penglai/penglai-enclave/Image -j$(nproc)
CROSS_COMPILE=riscv64-unknown-linux-gnu- make O=build-oe/qemu-virt PLATFORM=generic FW_PAYLOAD=y FW_PAYLOAD_PATH=/home/zhaoxi/ipads/Penglai-Enclave-sPMP/u-boot.bin -j$(nproc)
#cp build-oe/qemu-virt/platform/qemu/virt/firmware/fw_payload.elf build-oe/qemu-virt/boot/fw_payload_oe_qemuvirt.elf
