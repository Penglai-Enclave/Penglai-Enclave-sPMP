#!/bin/bash
qemu-system-riscv64 -nographic -machine virt \
	-smp 4 -m 2G \
	-bios  ./opensbi-1.2/build-oe/qemu-virt/platform/generic/firmware/fw_payload.bin  \
	-drive file=openEuler-23.03-V1-base-qemu-preview.qcow2,format=qcow2,id=hd0 \
	-object rng-random,filename=/dev/urandom,id=rng0 \
	-device virtio-rng-device,rng=rng0 \
	-device virtio-blk-device,drive=hd0  \
	-device virtio-net-device,netdev=usernet \
	-netdev user,id=usernet,hostfwd=tcp::12055-:22 \
	-device qemu-xhci -usb -device usb-kbd -device usb-tablet
	# -append 'root=/dev/vda1 rw console=ttyS0 earlycon=sbi systemd.default_timeout_start_sec=600 selinux=0 highres=off mem=4096M earlycon' \
	# -bios none
	# -bios  fw_payload_oe_uboot_2304.bin  \
## For v1.0, use the following path
	#-kernel  ./opensbi-1.0/build-oe/qemu-virt/platform/generic/firmware/fw_payload.elf  \

## For v0.9, use the following path
	#-kernel  ./opensbi-0.9/build-oe/qemu-virt/platform/generic/firmware/fw_payload.elf  \

## For v0.6, use the following path
	#-kernel  ./opensbi-0.6/build-oe/qemu-virt/platform/qemu/virt/firmware/fw_payload.elf  \
