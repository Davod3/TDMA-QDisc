ifneq (${KERNELRELEASE},)

obj-m := sch_tdma.o

else

KDIR := /lib/modules/`uname -r`/build
MDIR := `pwd`

default:
	$(MAKE) -C $(KDIR) M=$(MDIR)

endif
