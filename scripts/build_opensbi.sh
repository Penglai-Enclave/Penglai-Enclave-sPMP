#!/bin/bash

## Author: Dong Du, dd_nirvana@sjtu.edu.cn
## Description: This script is for building opensbi v0.9
## 		For older version (e.g., v0.6), please find other scripts
opensbi_version=1.2
kernel_version=2003

function build_opensbi_1() {
    # build opensbi
    cd ./opensbi-${1}
	make O=build-oe/qemu-virt clean
	mkdir -p build-oe/qemu-virt
	CROSS_COMPILE=riscv64-unknown-linux-gnu- make O=build-oe/qemu-virt PLATFORM=generic FW_PAYLOAD=y FW_PAYLOAD_PATH=../Image
#cp build-oe/qemu-virt/platform/qemu/virt/firmware/fw_payload.elf build-oe/qemu-virt/boot/fw_payload_oe_qemuvirt.elf
}

function build_opensbi_2() {
    cd ./opensbi-${1}
    rm -rf build-oe/qemu-virt
    mkdir -p build-oe/qemu-virt
    CROSS_COMPILE=riscv64-unknown-linux-gnu- make O=build-oe/qemu-virt PLATFORM=generic FW_PAYLOAD=y FW_PAYLOAD_PATH=../Penglai-Enclave-sPMP/u-boot/u-boot.bin -j$(nproc)
}

function print_usage() {
	RED='\033[0;31m'
	BLUE='\033[0;34m'
	BOLD='\033[1m'
	NONE='\033[0m'

	echo -e "\n${RED}Usage${NONE}:
	.${BOLD}/build_opensbi.sh${NONE} [OPTION]"

	echo -e "\n${RED}OPTIONS${NONE}:
	${BLUE}-v${NONE}: Select the opensbi version,default use 1.2
	${BLUE}-k${NONE}: Select the openeuler version,default use openEuler-2003
    help: print usage
	"
}

if [[ $1 == *"help"* ]]; then
	print_usage
	exit 0
fi

while getopts ":v:k:" opt; do
  case $opt in
    v)
      opensbi_version=$OPTARG
      ;;
	k)
	  kernel_version=$OPTARG
	  ;;
	\?)
      echo "Invalid option: -$OPTARG" >&2
	  print_usage
	  exit 1
      ;;
  esac
done


if [ $(echo "$kernel_version < 2303" | bc -l) -eq 1 ]
then
	build_opensbi_1  $opensbi_version
	exit 0
else
	build_opensbi_2  $opensbi_version
	exit 0
fi