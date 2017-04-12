.PHONY: all

CHECK_PATCH=./checkpatch.pl --no-tree

ifneq ($(KERNELRELEASE),)

  obj-m := kshell.o

else
  KERNELDIR ?= /lib/modules/$(shell uname -r)/build
  PWD := $(shell pwd)

all :
	make -C $(KERNELDIR) M=$(PWD) modules

check :
	for f in *.c *.h; do \
		$(CHECK_PATCH) -f $$f; \
	done

in :
	insdev kshell

out:
	rmdev kshell

run: comp
	./test

comp:
	gcc -o test test.c

clean:
	make -C $(KERNELDIR) M=$(PWD) clean
	rm test
endif
