.PHONY: all

CHECK_PATCH=./checkpatch.pl --no-tree

ifneq ($(KERNELRELEASE),)

  obj-m := kshell.o

else
  KERNELDIR ?= /Vrac/linux-4.2.3/
  PWD := $(shell pwd)

all :
	make -C $(KERNELDIR) M=$(PWD) modules

check:
	$(CHECK_PATCH) --no-tree -f common.h;
	$(CHECK_PATCH) --no-tree -f kshell.h;
	$(CHECK_PATCH) --no-tree -f kshell.c;

clean:
	make -C $(KERNELDIR) M=$(PWD) clean

endif

