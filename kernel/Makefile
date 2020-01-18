
ifndef $(KERNEL_DIR)
KERNEL_DIR := /lib/modules/$(shell uname -r)/build
endif

obj-m := ipt_sk_helper.o

all:	modules

modules:
	make -C ${KERNEL_DIR} M=$$PWD $@ $(MFLAGS)
modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	depmod -a;
clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;
	rm -rf modules.order
