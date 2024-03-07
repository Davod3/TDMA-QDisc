obj-m += tdma.o
# tdma-objs += create_packet.o #netlink_sock.o

obj-m += qdisc.o
# tdma-objs += create_packet.o #netlink_sock.o

.PHONY: all netcntl

all: netcntl
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

netcntl:
	@$(MAKE) -C netcntl

install:
	sudo insmod qdisc.ko
	sudo insmod tdma.ko

remove:
	sudo rmmod qdisk.ko
	sudo rmmod tdma.ko
clean:
	# rm -f tap trace.bt
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

