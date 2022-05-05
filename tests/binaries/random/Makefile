RISCV_GCC=/home/nicolas/Downloads/riscv64-lp64d--glibc--stable-2021.11-1/bin/riscv64-linux-gcc
MIPSEL_GCC=/home/nicolas/Downloads/mips32el--glibc--stable-2018.11-1/bin/mipsel-linux-gcc

all: arm64 intel-x86-32 intel-x86-64 mipsel-32 riscv-64


arm64: checkrandom.c
	arm-linux-gnueabi-gcc checkrandom.c -static -g -O0 -o checkrandom-arm.bin
intel-x86-64: checkrandom.c
	gcc -g -O0 checkrandom.c -static -o checkrandom-x86-64.bin
intel-x86-32: checkrandom.c
	gcc -g -O0 checkrandom.c -static -m32 -o checkrandom-x86-32.bin
mipsel-32: checkrandom.c
	$(MIPSEL_GCC) -g -O0 checkrandom.c -static -o checkrandom-mipsel32.bin
riscv-64: checkrandom.c
	$(RISCV_GCC) -g -O0 checkrandom.c -static -o checkrandom-riscv64.bin


intel64-dump-main: checkrandom-x86-64.bin
	objdump -M intel -S checkrandom-x86-64.bin | grep "<main>:" -A 50
intel32-dump-main: checkrandom-x86-32.bin
	objdump -M intel -S checkrandom-x86-32.bin | grep "<main>:" -A 50
arm-dump-main: checkrandom-arm.bin
	arm-linux-gnueabi-objdump -S -d checkrandom-arm.bin | grep "<main>:" -A 50

.PHONY: intel64-dump-main intel32-dump-main arm-dump-main clean

clean:
	rm *.bin
