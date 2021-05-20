PENGLAI_SDK       ?= $(shell pwd)
RISCV_TOOLCHAIN   ?= $(shell readlink -f ../work/buildroot_initramfs/host/bin)
CROSS_COMPILE     ?= $(RISCV_TOOLCHAIN)/riscv-nuclei-linux-gnu-
BUILDROOT_SYSROOT ?= $(shell readlink -f ../work/buildroot_initramfs_sysroot)

export PENGLAI_SDK
export CROSS_COMPILE

# Compiler tools definitions
CC     := $(CROSS_COMPILE)gcc
CXX    := $(CROSS_COMPILE)g++
LINK   := $(CROSS_COMPILE)ld
AS     := $(CROSS_COMPILE)as
AR     := $(CROSS_COMPILE)ar
STRIP  := $(CROSS_COMPILE)strip
RANLIB := $(CROSS_COMPILE)ranlib

# Need to export extra compiler variables
export CC
export CXX
export LINK
export AR
export AS
export STRIP
export RANLIB

all:
	make -C musl
	make -C lib
	make -C demo

copy: all
	cp demo/host/host $(BUILDROOT_SYSROOT)/root/
	cp demo/prime/prime $(BUILDROOT_SYSROOT)/root/
	cp demo/aes/aes $(BUILDROOT_SYSROOT)/root/

clean:
	make -C musl clean
	make -C lib clean
	make -C demo clean
