#!/bin/bash
qemu-system-riscv64 -nographic -machine virt \
	-smp 1 -m 2G \
	-kernel  ./opensbi-0.9/build-oe/qemu-virt/platform/generic/firmware/fw_payload.elf  \
	-drive file=openEuler-preview.riscv64.qcow2,format=qcow2,id=hd0 \
	-object rng-random,filename=/dev/urandom,id=rng0 \
	-device virtio-rng-device,rng=rng0 \
	-device virtio-blk-device,drive=hd0  \
	-device virtio-net-device,netdev=usernet \
	-netdev user,id=usernet,hostfwd=tcp::12055-:22 \
	-append 'root=/dev/vda1 rw console=ttyS0 systemd.default_timeout_start_sec=600 selinux=0 highres=off mem=4096M earlycon' \
	-bios none

## For v1.0, use the following path
	#-kernel  ./opensbi-1.0/build-oe/qemu-virt/platform/generic/firmware/fw_payload.elf  \

## For v0.9, use the following path
	#-kernel  ./opensbi-0.9/build-oe/qemu-virt/platform/generic/firmware/fw_payload.elf  \

## For v0.6, use the following path
	#-kernel  ./opensbi-0.6/build-oe/qemu-virt/platform/qemu/virt/firmware/fw_payload.elf  \
