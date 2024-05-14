obj-m += kernelValue2cache.o

CC=gcc
ccflags-y += "-g"
ccflags-y += "-O2"

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
