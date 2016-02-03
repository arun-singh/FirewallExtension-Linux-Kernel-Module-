KERNELDIR=/lib/modules/`uname -r`/build
#ARCH=i386
#KERNELDIR=/usr/src/kernels/`uname -r`-i686

MODULES = firewallExtension.ko findExecutable.ko
PROGS = firewallSetup

 
obj-m += firewallExtension.o findExecutable.o

all:
	make -C  $(KERNELDIR) M=$(PWD) modules
	make firewallSetup

clean:
	make -C $(KERNELDIR) M=$(PWD) clean
	rm -f $(PROGS) *.o

install:	
	make -C $(KERNELDIR) M=$(PWD) modules_install

quickInstall:
	cp $(MODULES) /lib/modules/`uname -r`/extra

firewallSetup: firewallSetup.o linked_list.o
	gcc -Wall -Werror firewallSetup.o linked_list.o -o firewallSetup 

firewallSetup.o: firewallSetup.c
	gcc -Wall -Werror -o firewallSetup.o -c firewallSetup.c

linked_list.o: linked_list.c
	gcc -Wall -Werror -o linked_list.o -c linked_list.c
