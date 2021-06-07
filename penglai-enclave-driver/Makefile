obj-m += penglai.o
penglai-objs := penglai-enclave-driver.o \
	penglai-enclave-elfloader.o \
	penglai-enclave-page.o \
	penglai-enclave.o \
	penglai-enclave-ioctl.o 

all:
	make -C ../openeuler-kernel/ ARCH=riscv M=$(PWD) modules

clean:
	make -C ../openeuler-kernel/ ARCH=riscv M=$(PWD) clean
