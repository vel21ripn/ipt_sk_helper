
ifndef $(KERNEL_DIR)
KERNEL_DIR := /lib/modules/$(shell uname -r)/build
endif


all:
	$(MAKE) -C kernel KERNEL_DIR=$(KERNEL_DIR)

modules_install:
	$(MAKE) -C kernel modules_install KERNEL_DIR=$(KERNEL_DIR)
clean:
	$(MAKE) -C kernel clean KERNEL_DIR=$(KERNEL_DIR)
