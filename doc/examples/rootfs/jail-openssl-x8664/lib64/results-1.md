# Microsurf Analysis Results (run: 03/14/2022, 16:44:08)
## Metadata 
### Binary
`/home/nicolas/Documents/msc-thesis-work/doc/examples/rootfs/jail-openssl-x8664/openssl`
 >ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 4.4.0, with debug_info, not stripped 

__Args__
`['camellia-128-ecb', '-e', '-in', 'input.bin', '-out', 'output.bin', '-nosalt', '-K', '33b0ee592bc3069601f122f4a82f31ee']` 
__Deterministic__
`False` 
__Emulation root__
`/home/nicolas/Documents/msc-thesis-work/doc/examples/rootfs/jail-openssl-x8664/` 
__Sample secret__
`28edb11a981476315412d8f5eae8cf42` 
__Leakage model__
`identity` 
## Results 
| offset | MI score | Function | Object |
|-----|-----|-----|-----|
| 0x0e9416 | 0.05 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x0e942a | 0.00 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x0e8e2b | 0.00 | _x86_64_Camellia_encrypt | libcrypto.so.1.1 |
| 0x0e9431 | 0.00 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x0e8e35 | 0.00 | _x86_64_Camellia_encrypt | libcrypto.so.1.1 |
| 0x0e943b | 0.79 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x0e943f | 0.05 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x0e944c | 0.01 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x0e9453 | 0.00 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x0e947c | 0.18 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x0e8e7d | 0.00 | _x86_64_Camellia_encrypt | libcrypto.so.1.1 |
| 0x0e9483 | 0.00 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x0e8e8a | 0.04 | _x86_64_Camellia_encrypt | libcrypto.so.1.1 |
| 0x0e9497 | 0.00 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x0e8e9f | 0.00 | _x86_64_Camellia_encrypt | libcrypto.so.1.1 |
| 0x0e94a1 | 0.05 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x0e94a5 | 0.06 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x0e8eac | 0.00 | _x86_64_Camellia_encrypt | libcrypto.so.1.1 |
| 0x0e94b2 | 0.04 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x0e94b9 | 0.13 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x0e8ee3 | 0.00 | _x86_64_Camellia_encrypt | libcrypto.so.1.1 |
| 0x0e8ef0 | 0.02 | _x86_64_Camellia_encrypt | libcrypto.so.1.1 |
| 0x0e94f9 | 0.03 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x0e8f01 | 0.00 | _x86_64_Camellia_encrypt | libcrypto.so.1.1 |
| 0x0e9506 | 0.00 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x0e950d | 0.00 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x0e9517 | 0.00 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x0e8f19 | 0.00 | _x86_64_Camellia_encrypt | libcrypto.so.1.1 |
| 0x0e8d44 | 0.03 | _x86_64_Camellia_encrypt | libcrypto.so.1.1 |
| 0x0e9558 | 0.20 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x0e8d58 | 0.00 | _x86_64_Camellia_encrypt | libcrypto.so.1.1 |
| 0x0e955f | 0.07 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x0e8d69 | 0.00 | _x86_64_Camellia_encrypt | libcrypto.so.1.1 |
| 0x0e8d6d | 0.06 | _x86_64_Camellia_encrypt | libcrypto.so.1.1 |
| 0x0e9573 | 0.13 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x0e8f78 | 0.00 | _x86_64_Camellia_encrypt | libcrypto.so.1.1 |
| 0x0e8d7a | 0.07 | _x86_64_Camellia_encrypt | libcrypto.so.1.1 |
| 0x0e957d | 0.12 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x0e9581 | 0.06 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x0e8d81 | 0.21 | _x86_64_Camellia_encrypt | libcrypto.so.1.1 |
| 0x0e958e | 0.09 | Camellia_Ekeygen | libcrypto.so.1.1 |
| 0x0e8daa | 0.00 | _x86_64_Camellia_encrypt | libcrypto.so.1.1 |
| 0x0e8dbe | 0.06 | _x86_64_Camellia_encrypt | libcrypto.so.1.1 |
| 0x0e8dc5 | 0.00 | _x86_64_Camellia_encrypt | libcrypto.so.1.1 |
| 0x0e8de7 | 0.00 | _x86_64_Camellia_encrypt | libcrypto.so.1.1 |
