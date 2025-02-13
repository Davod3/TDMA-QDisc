EXTRA_CFLAGS += -std=gnu99

# build modules
obj-m += tdma.o 
obj-m += topology.o
obj-m += ratdma.o

# Kernel src directory
KDIR = /lib/modules/$(shell uname -r)/build
.PHONY: all netcntlr

# build all modules
all: netcntlr 
	$(MAKE) -C $(KDIR) M=$(PWD) EXTRA_CFLAGS="$(EXTRA_CFLAGS)" modules
	rm -r -f *.mod.c .*.cmd *.symvers *.o

# (sub)build user-space program
# invokes 'Makefile' in netcntl directory
netcntlr:
	@$(MAKE) -C netcntlr

# ensure correct ordering of module insertion
install:
	sudo insmod topology.ko
	sudo insmod ratdma.ko
	sudo insmod tdma.ko

# remove modules in reverse order of insertion
remove:
	sudo rmmod tdma.ko
	sudo rmmod ratdma.ko
	sudo rmmod topology.ko

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	@$(MAKE) -C netcntlr clean

