CC=/home/nicolas/Downloads/armv7-eabihf--glibc--stable-2018.11-1/bin/arm-linux-gcc
CFLAGS= -gdwarf-4 -march=armv7 -mthumb -mfloat-abi=hard -I./include/ -I./include/cyassl -I./include/cyassl/ctaocrypt -I./include/cyassl/openssl -I./include/wolfssl -I./include/wolfssl/wolfcrypt -I./include/wolfssl/openssl
LIBS= -L./lib -lwolfssl

all: aes-file-encrypt

aes-file-encrypt: aes-file-encrypt.o
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS) 