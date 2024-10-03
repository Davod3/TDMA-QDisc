# build modules
obj-m += tdma.o 

# Kernel src directory
KDIR = /lib/modules/$(shell uname -r)/build
.PHONY: all netcntlr

# build all modules
all: netcntlr 
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# (sub)build user-space program
# invokes 'Makefile' in netcntl directory
netcntlr:
	@$(MAKE) -C netcntlr

# ensure correct ordering of module insertion
install:
	sudo insmod tdma.ko

# remove modules in reverse order of insertion
remove:
	sudo rmmod tdma.ko

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	@$(MAKE) -C netcntlr clean

