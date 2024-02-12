# obj-m += tdma.o
# tdma-objs += create_packet.o #netlink_sock.o

obj-m += qdisc.o
# tdma-objs += create_packet.o #netlink_sock.o

all:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules


clean:
	$(MAKE) -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

