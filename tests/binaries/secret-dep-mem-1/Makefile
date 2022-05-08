RISCV_GCC=/home/nicolas/Downloads/riscv64-lp64d--glibc--stable-2021.11-1/bin/riscv64-linux-gcc
MIPSEL_GCC=/home/nicolas/Downloads/mips32el--glibc--stable-2018.11-1/bin/mipsel-linux-gcc
ARM_GCC=/opt/arm/9/gcc-arm-9.2-2019.12-x86_64-aarch64-none-linux-gnu/bin/aarch64-none-linux-gnu-gcc

all: arm64 intel-x86-32 intel-x86-64 mipsel-32 riscv-64

SRC_FILE=secret-dep-mem-1.c

C_FLAGS= -gdwarf-4 -O0 -Werror -static

arm64: $(SRC_FILE)
	$(ARM_GCC) $(SRC_FILE) $(C_FLAGS)  -o secret-dep-mem-1-arm.bin
intel-x86-64: $(SRC_FILE)
	gcc $(SRC_FILE) $(C_FLAGS) -o secret-dep-mem-1-x86-64.bin
intel-x86-32: $(SRC_FILE)
	gcc $(SRC_FILE) $(C_FLAGS) -m32 -o secret-dep-mem-1-x86-32.bin
mipsel-32: $(SRC_FILE)
	$(MIPSEL_GCC) $(C_FLAGS) -O0 $(SRC_FILE) -o secret-dep-mem-1-mipsel32.bin
riscv-64: $(SRC_FILE)
	$(RISCV_GCC) $(C_FLAGS) -O0 $(SRC_FILE) -o secret-dep-mem-1-riscv64.bin


.PHONY: clean

clean:
	rm *.bin
