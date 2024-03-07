ifeq (${KERNELRELEASE},)

KDIR := /lib/modules/`uname -r`/build
MDIR := `pwd`

default:
	$(MAKE) -C $(KDIR) M=$(MDIR)

else

obj-m := sch_tbf_test.o

endif
