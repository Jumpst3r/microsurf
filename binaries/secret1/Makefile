all: arm intel-ia32 intel-x86-64


arm: secret.c
	arm-linux-gnueabi-gcc secret.c -static -g -O0 -o secret-arm.bin
intel-x86-64: secret.c
	gcc -g -O0 secret.c -static -o secret-x86-64.bin
intel-ia32: secret.c
	gcc -g -O0 secret.c -static -m32 -o secret-x86-32.bin



intel64-dump-main: secret-x86-64.bin
	objdump -M intel -S secret-x86-64.bin | grep "<main>:" -A 50
intel32-dump-main: secret-x86-32.bin
	objdump -M intel -S secret-x86-32.bin | grep "<main>:" -A 50
arm-dump-main: secret-arm.bin
	arm-linux-gnueabi-objdump -S -d secret-arm.bin | grep "<main>:" -A 50

.PHONY: intel64-dump-main intel32-dump-main arm-dump-main