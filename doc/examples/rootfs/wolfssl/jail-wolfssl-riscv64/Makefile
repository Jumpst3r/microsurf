CC=/home/nicolas/Downloads/riscv64-lp64d--glibc--stable-2021.11-1/bin/riscv64-linux-gcc
CFLAGS= -gdwarf-4 -I./include/ -I./include/cyassl -I./include/cyassl/ctaocrypt -I./include/cyassl/openssl -I./include/wolfssl -I./include/wolfssl/wolfcrypt -I./include/wolfssl/openssl
LIBS= -L./lib -lwolfssl

all: aes-file-encrypt

aes-file-encrypt: aes-file-encrypt.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) 