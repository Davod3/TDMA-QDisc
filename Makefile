# build modules
obj-m += tdma.o 
obj-m += netlink_sock.o
obj-m += qdisc.o

# Kernel src directory
KDIR = /lib/modules/$(shell uname -r)/build
.PHONY: all netcntl

# build all modules
all: netcntl
	$(MAKE) -C $(KDIR) M=$(PWD) modules

# (sub)build user-space program
# invokes 'Makefile' in netcntl directory
netcntl:
	@$(MAKE) -C netcntl

# ensure correct ordering of module insertion
install:
	sudo insmod qdisc.ko
	sudo insmod tdma.ko
	sudo insmod netlink_sock.ko

# remove modules in reverse order of insertion
remove:
	sudo rmmod qdisc.ko
	sudo rmmod netlink_sock.ko
	sudo rmmod tdma.ko

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	@$(MAKE) -C netcntl clean

