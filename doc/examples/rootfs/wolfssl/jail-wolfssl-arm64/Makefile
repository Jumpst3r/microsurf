CC=/home/nicolas/Downloads/aarch64--glibc--stable-2020.02-1/bin/aarch64-linux-gcc
CFLAGS=-I./include/ -I./include/cyassl -I./include/cyassl/ctaocrypt -I./include/cyassl/openssl -I./include/wolfssl -I./include/wolfssl/wolfcrypt -I./include/wolfssl/openssl
LIBS= -L./lib -lwolfssl

all: aes-file-encrypt

aes-file-encrypt: aes-file-encrypt.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) 
