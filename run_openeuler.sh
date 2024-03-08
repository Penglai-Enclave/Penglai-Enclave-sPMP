#!/bin/bash

kernel_version=2003
opensbi_version=1.2

function print_usage() {
	RED='\033[0;31m'
	BLUE='\033[0;34m'
	BOLD='\033[1m'
	NONE='\033[0m'

	echo -e "\n${RED}Usage${NONE}:
	.${BOLD}/run_openeuler.sh${NONE} [OPTION]"

	echo -e "\n${RED}OPTIONS${NONE}:
	${BLUE}-k${NONE}: Select the openeuler version,default use openEuler2003
	${BLUE}-o${NONE}: Select the opensbi version,default use opensbi-1.2
	"
	echo -e "\n${RED}EXAMPLE${NONE}:
	${BLUE}./run_openeuler.sh -k 2003 -o 1.2${NONE}"
}

if [[ $1 == *"help"* ]]; then
	print_usage
	exit 0
fi

while getopts ":k:o:" opt; do
  case $opt in
    k)
      kernel_version=$OPTARG
      ;;
    o)
      opensbi_version=$OPTARG
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
	  print_usage
	  exit 1
      ;;
  esac
done

imagepath=openEuler-$kernel_version-qemu-riscv64.qcow2

if [ $(echo "$opensbi_version == 0.9" | bc -l) -eq 1 ]
then
    opensbi_path=opensbi-0.9
elif [ $(echo "$opensbi_version == 1.0" | bc -l) -eq 1 ]
then
	opensbi_path=opensbi-1.0
elif [ $(echo "$opensbi_version == 1.2" | bc -l) -eq 1 ]
then
	opensbi_path=opensbi-1.2
else
	echo "Invalid opensbi version: $opensbi_version" >&2
	print_usage
	exit 1
fi


function run_qemu_1(){
	qemu-system-riscv64 -nographic -machine virt \
	-smp 4 -m 2G \
	-kernel  ./${2}/build-oe/qemu-virt/platform/generic/firmware/fw_payload.elf  \
	-drive file=${1},format=qcow2,id=hd0 \
	-object rng-random,filename=/dev/urandom,id=rng0 \
	-device virtio-rng-device,rng=rng0 \
	-device virtio-blk-device,drive=hd0  \
	-device virtio-net-device,netdev=usernet \
	-netdev user,id=usernet,hostfwd=tcp::12055-:22 \
	-append 'root=/dev/vda1 rw console=ttyS0 systemd.default_timeout_start_sec=600 selinux=0 highres=off mem=4096M earlycon' \
	-bios none
}

function run_qemu_2(){
	qemu-system-riscv64 -nographic -machine virt \
			-smp 4 -m 2G \
			-bios  ./${2}/build-oe/qemu-virt/platform/generic/firmware/fw_payload.bin  \
			-drive file=${1},format=qcow2,id=hd0 \
			-object rng-random,filename=/dev/urandom,id=rng0 \
			-device virtio-rng-device,rng=rng0 \
			-device virtio-blk-device,drive=hd0  \
			-device virtio-net-device,netdev=usernet \
			-netdev user,id=usernet,hostfwd=tcp::12055-:22 \
			-device qemu-xhci -usb -device usb-kbd -device usb-tablet
}

if ((kernel_version < 2303))
then
	echo "Run openEuer $kernel_version with opensbi $opensbi_version"
	run_qemu_1 $imagepath $opensbi_path
	exit 0
else
	echo "Run openEuer $kernel_version with opensbi $opensbi_version"
	run_qemu_2 $imagepath $opensbi_path
	exit 0
fi

## For v1.0, use the following path
	#-kernel  ./opensbi-1.0/build-oe/qemu-virt/platform/generic/firmware/fw_payload.elf  \

## For v0.9, use the following path
	#-kernel  ./opensbi-0.9/build-oe/qemu-virt/platform/generic/firmware/fw_payload.elf  \

## For v0.6, use the following path
	#-kernel  ./opensbi-0.6/build-oe/qemu-virt/platform/qemu/virt/firmware/fw_payload.elf  \
