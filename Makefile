all:
	$(MAKE) -C kernel

modules_install:
	$(MAKE) -C kernel modules_install
clean:
	$(MAKE) -C kernel clean
