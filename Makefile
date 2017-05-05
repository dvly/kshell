.PHONY: all

CHECK_PATCH=./checkpatch.pl --no-tree

ifneq ($(KERNELRELEASE),)

  obj-m := kshell.o

else
  KERNELDIR ?= /Vrac/linux-4.2.3/
  PWD := $(shell pwd)

all :
	make -C $(KERNELDIR) M=$(PWD) modules

cp:
	cp kshell.ko ../tosend/kshell.ko

check:
	$(CHECK_PATCH) -f kshell.c

check_test:
	for f in *.c *.h; do
		$(CHECK_PATCH) --no-tree -f $$f
	done

clean:
	make -C $(KERNELDIR) M=$(PWD) clean

endif

