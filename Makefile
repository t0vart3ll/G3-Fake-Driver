# Makefile for compiling the kernel module and user-space application

KERNELDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

obj-m += g3_fake.o

all: modules app_g3_fake fuzzing_app app_g3_unified

# Compile the kernel module
modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

# Compile the user-space applications
app_g3_fake: app_g3_fake.c
	gcc -o app_g3_fake app_g3_fake.c -lpthread

fuzzing_app: fuzzing_app.c
	gcc -o fuzzing_app fuzzing_app.c -lpthread

# Unified application (recommended)
app_g3_unified: app_g3_unified.c
	gcc -o app_g3_unified app_g3_unified.c -lpthread

clean:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) clean
	rm -f app_g3_fake fuzzing_app app_g3_unified
