# Microsurf Analysis Results (run: 03/14/2022, 16:59:25)

## Metadata

### Binary

`/home/nicolas/Documents/msc-thesis-work/doc/examples/rootfs/jail-openssl-x8632/openssl`
> ELF 32-bit LSB pie executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2,
> BuildID[sha1]=4b59a03925ae04b1b105a268685df59d7ed9bd1b, for GNU/Linux 3.2.0, not stripped

__Args__
`['camellia-128-ecb', '-e', '-in', 'input.bin', '-out', 'output.bin', '-nosalt', '-K', '4f2b82b5dfd57d053293b275fdc5ea75']`
__Deterministic__
`False`
__Emulation root__
`/home/nicolas/Documents/msc-thesis-work/doc/examples/rootfs/jail-openssl-x8632/`
__Sample secret__
`356231df9836f1a7186c37c7c0811bfd`
__Leakage model__
`identity`

## Results

| offset | MI score | Function | Object |
|-----|-----|-----|-----|
| 0x08f61e | 0.05 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x08f621 | 0.06 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x090022 | 0.03 | Camellia_EncryptBlock_Rounds | libcrypto.so.1.1 |
| 0x090025 | 0.10 | Camellia_EncryptBlock_Rounds | libcrypto.so.1.1 |
| 0x08f634 | 0.00 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x08f63b | 0.00 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x09003c | 0.00 | Camellia_EncryptBlock_Rounds | libcrypto.so.1.1 |
| 0x08f649 | 0.00 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x09004a | 0.04 | Camellia_EncryptBlock_Rounds | libcrypto.so.1.1 |
| 0x08f657 | 0.00 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x09005d | 0.00 | Camellia_EncryptBlock_Rounds | libcrypto.so.1.1 |
| 0x08f663 | 0.00 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x090064 | 0.00 | Camellia_EncryptBlock_Rounds | libcrypto.so.1.1 |
| 0x08f66a | 0.00 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x08f48a | 0.62 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x08f48d | 0.22 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x08f49d | 0.21 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x08f4a7 | 0.00 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x0900aa | 0.00 | Camellia_EncryptBlock_Rounds | libcrypto.so.1.1 |
| 0x08f4ba | 0.00 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x08f4c1 | 0.00 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x08f4cd | 0.00 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x08f4d8 | 0.01 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x08f50c | 0.05 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x08f50f | 0.13 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x08f51f | 0.00 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x08f526 | 0.00 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x08f53b | 0.00 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x08f547 | 0.00 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x08f552 | 0.00 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x090183 | 0.04 | Camellia_EncryptBlock_Rounds | libcrypto.so.1.1 |
| 0x08f59a | 0.33 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x08f59d | 0.00 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x08ffa8 | 0.13 | Camellia_EncryptBlock_Rounds | libcrypto.so.1.1 |
| 0x08f5aa | 0.00 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x08f5b6 | 0.03 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x08ffbe | 0.00 | Camellia_EncryptBlock_Rounds | libcrypto.so.1.1 |
| 0x08f5cd | 0.41 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x08f5d4 | 0.05 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x08f5e0 | 0.28 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x08f5eb | 0.15 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x08fff1 | 0.00 | Camellia_EncryptBlock_Rounds | libcrypto.so.1.1 |
| 0x0901fa | 0.08 | Camellia_EncryptBlock_Rounds | libcrypto.so.1.1 |
