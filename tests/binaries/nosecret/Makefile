all: arm intel-ia32 intel-x86-64


arm: nosecret.c
	arm-linux-gnueabi-gcc nosecret.c -static -g -O0 -o nosecret-arm.bin
intel-x86-64: nosecret.c
	gcc -g -O0 nosecret.c -static -o nosecret-x86-64.bin
intel-ia32: nosecret.c
	gcc -g -O0 nosecret.c -static -m32 -o nosecret-x86-32.bin



intel64-dump-main: nosecret-x86-64.bin
	objdump -M intel -S nosecret-x86-64.bin | grep "<main>:" -A 50
intel32-dump-main: nosecret-x86-32.bin
	objdump -M intel -S nosecret-x86-32.bin | grep "<main>:" -A 50
arm-dump-main: nosecret-arm.bin
	arm-linux-gnueabi-objdump -S -d nosecret-arm.bin | grep "<main>:" -A 50

.PHONY: intel64-dump-main intel32-dump-main arm-dump-main