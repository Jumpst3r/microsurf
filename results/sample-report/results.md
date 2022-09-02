# Microsurf Analysis Results

__Run at__: 09/02/2022, 14:55:56 

__Elapsed time (analysis)__: 00:04:02 

__Elapsed time (single run emulation)__: 0:00:00.204446 

__Total leak count__: 66 

__Binary__: `docs/examples/rootfs/openssl/jail-openssl-1.1.1dev-x8664/openssl`
 >ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 4.4.0, with debug_info, not stripped 

__Args__: `['bf-ecb', '-in', 'input.bin', '-out', 'output.bin', '-nosalt', '-K', '@']` 

__Emulation root__: `docs/examples/rootfs/openssl/jail-openssl-1.1.1dev-x8664/` 

__Table of contents:__

[TOC] 

## Overview by function name
| Symbol Name                                     |   Memory Leak Count |   CF Leak Count |
|:------------------------------------------------|--------------------:|----------------:|
| BF_encrypt                                      |                  64 |               0 |
| OPENSSL_hexchar2int                             |                   1 |               0 |
| set_hex (or) ASN1_generate_nconf@@OPENSSL_1_1_0 |                   1 |               0 |

### Leaks for BF_encrypt

| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b0df | 0x0ab0df | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:47 |

Source code snippet

```C
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);
    BF_ENC(l, r, s, p[16]);
# if BF_ROUNDS == 20
    BF_ENC(r, l, s, p[17]);

```


Leaking instruction

```
[0xab0df] : mov        r8d, dword ptr [rax + r8*4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b003 | 0x0ab003 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:43 |

Source code snippet

```C
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);

```


Leaking instruction

```
[0xab003] : xor        r8d, dword ptr [rax + rbx*4 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b00b | 0x0ab00b | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:43 |

Source code snippet

```C
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);

```


Leaking instruction

```
[0xab00b] : add        r8d, dword ptr [rax + r9*4 + 0xc00]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b02e | 0x0ab02e | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:44 |

Source code snippet

```C
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);

```


Leaking instruction

```
[0xab02e] : mov        r8d, dword ptr [rax + r8*4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b032 | 0x0ab032 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:44 |

Source code snippet

```C
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);

```


Leaking instruction

```
[0xab032] : add        r8d, dword ptr [rax + r9*4 + 0x400]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b03e | 0x0ab03e | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:44 |

Source code snippet

```C
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);

```


Leaking instruction

```
[0xab03e] : xor        r8d, dword ptr [rax + rbx*4 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b046 | 0x0ab046 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:44 |

Source code snippet

```C
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);

```


Leaking instruction

```
[0xab046] : add        r8d, dword ptr [rax + r9*4 + 0xc00]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b069 | 0x0ab069 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:45 |

Source code snippet

```C
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);
    BF_ENC(l, r, s, p[16]);

```


Leaking instruction

```
[0xab069] : mov        r8d, dword ptr [rax + r8*4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b06d | 0x0ab06d | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:45 |

Source code snippet

```C
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);
    BF_ENC(l, r, s, p[16]);

```


Leaking instruction

```
[0xab06d] : add        r8d, dword ptr [rax + r9*4 + 0x400]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b079 | 0x0ab079 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:45 |

Source code snippet

```C
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);
    BF_ENC(l, r, s, p[16]);

```


Leaking instruction

```
[0xab079] : xor        r8d, dword ptr [rax + rbx*4 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b081 | 0x0ab081 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:45 |

Source code snippet

```C
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);
    BF_ENC(l, r, s, p[16]);

```


Leaking instruction

```
[0xab081] : add        r8d, dword ptr [rax + r9*4 + 0xc00]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b0a4 | 0x0ab0a4 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:46 |

Source code snippet

```C
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);
    BF_ENC(l, r, s, p[16]);
# if BF_ROUNDS == 20

```


Leaking instruction

```
[0xab0a4] : mov        r8d, dword ptr [rax + r8*4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b0a8 | 0x0ab0a8 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:46 |

Source code snippet

```C
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);
    BF_ENC(l, r, s, p[16]);
# if BF_ROUNDS == 20

```


Leaking instruction

```
[0xab0a8] : add        r8d, dword ptr [rax + r9*4 + 0x400]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b0b4 | 0x0ab0b4 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:46 |

Source code snippet

```C
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);
    BF_ENC(l, r, s, p[16]);
# if BF_ROUNDS == 20

```


Leaking instruction

```
[0xab0b4] : xor        r8d, dword ptr [rax + rbx*4 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b0bc | 0x0ab0bc | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:46 |

Source code snippet

```C
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);
    BF_ENC(l, r, s, p[16]);
# if BF_ROUNDS == 20

```


Leaking instruction

```
[0xab0bc] : add        r8d, dword ptr [rax + r9*4 + 0xc00]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b0e3 | 0x0ab0e3 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:47 |

Source code snippet

```C
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);
    BF_ENC(l, r, s, p[16]);
# if BF_ROUNDS == 20
    BF_ENC(r, l, s, p[17]);

```


Leaking instruction

```
[0xab0e3] : add        r8d, dword ptr [rax + r9*4 + 0x400]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0ae14 | 0x0aae14 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:35 |

Source code snippet

```C
    l = data[0];
    r = data[1];

    l ^= p[0];
    BF_ENC(r, l, s, p[1]);
    BF_ENC(l, r, s, p[2]);
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);

```


Leaking instruction

```
[0xaae14] : mov        r8d, dword ptr [rax + r8*4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b0ef | 0x0ab0ef | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:47 |

Source code snippet

```C
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);
    BF_ENC(l, r, s, p[16]);
# if BF_ROUNDS == 20
    BF_ENC(r, l, s, p[17]);

```


Leaking instruction

```
[0xab0ef] : xor        r8d, dword ptr [rax + rbx*4 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b0f7 | 0x0ab0f7 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:47 |

Source code snippet

```C
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);
    BF_ENC(l, r, s, p[16]);
# if BF_ROUNDS == 20
    BF_ENC(r, l, s, p[17]);

```


Leaking instruction

```
[0xab0f7] : add        r8d, dword ptr [rax + r9*4 + 0xc00]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b11a | 0x0ab11a | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:48 |

Source code snippet

```C
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);
    BF_ENC(l, r, s, p[16]);
# if BF_ROUNDS == 20
    BF_ENC(r, l, s, p[17]);
    BF_ENC(l, r, s, p[18]);

```


Leaking instruction

```
[0xab11a] : mov        r8d, dword ptr [rax + r8*4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b11e | 0x0ab11e | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:48 |

Source code snippet

```C
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);
    BF_ENC(l, r, s, p[16]);
# if BF_ROUNDS == 20
    BF_ENC(r, l, s, p[17]);
    BF_ENC(l, r, s, p[18]);

```


Leaking instruction

```
[0xab11e] : add        r8d, dword ptr [rax + r9*4 + 0x400]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b12a | 0x0ab12a | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:48 |

Source code snippet

```C
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);
    BF_ENC(l, r, s, p[16]);
# if BF_ROUNDS == 20
    BF_ENC(r, l, s, p[17]);
    BF_ENC(l, r, s, p[18]);

```


Leaking instruction

```
[0xab12a] : xor        r8d, dword ptr [rax + rbx*4 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b132 | 0x0ab132 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:48 |

Source code snippet

```C
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);
    BF_ENC(l, r, s, p[16]);
# if BF_ROUNDS == 20
    BF_ENC(r, l, s, p[17]);
    BF_ENC(l, r, s, p[18]);

```


Leaking instruction

```
[0xab132] : add        r8d, dword ptr [rax + r9*4 + 0xc00]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b156 | 0x0ab156 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:49 |

Source code snippet

```C
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);
    BF_ENC(l, r, s, p[16]);
# if BF_ROUNDS == 20
    BF_ENC(r, l, s, p[17]);
    BF_ENC(l, r, s, p[18]);
    BF_ENC(r, l, s, p[19]);

```


Leaking instruction

```
[0xab156] : mov        edx, dword ptr [rax + rdx*4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b159 | 0x0ab159 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:49 |

Source code snippet

```C
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);
    BF_ENC(l, r, s, p[16]);
# if BF_ROUNDS == 20
    BF_ENC(r, l, s, p[17]);
    BF_ENC(l, r, s, p[18]);
    BF_ENC(r, l, s, p[19]);

```


Leaking instruction

```
[0xab159] : add        edx, dword ptr [rax + r9*4 + 0x400]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b165 | 0x0ab165 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:49 |

Source code snippet

```C
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);
    BF_ENC(l, r, s, p[16]);
# if BF_ROUNDS == 20
    BF_ENC(r, l, s, p[17]);
    BF_ENC(l, r, s, p[18]);
    BF_ENC(r, l, s, p[19]);

```


Leaking instruction

```
[0xab165] : xor        edx, dword ptr [rax + rbx*4 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b16c | 0x0ab16c | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:49 |

Source code snippet

```C
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);
    BF_ENC(l, r, s, p[16]);
# if BF_ROUNDS == 20
    BF_ENC(r, l, s, p[17]);
    BF_ENC(l, r, s, p[18]);
    BF_ENC(r, l, s, p[19]);

```


Leaking instruction

```
[0xab16c] : add        edx, dword ptr [rax + r9*4 + 0xc00]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b192 | 0x0ab192 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:50 |

Source code snippet

```C
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);
    BF_ENC(l, r, s, p[16]);
# if BF_ROUNDS == 20
    BF_ENC(r, l, s, p[17]);
    BF_ENC(l, r, s, p[18]);
    BF_ENC(r, l, s, p[19]);
    BF_ENC(l, r, s, p[20]);

```


Leaking instruction

```
[0xab192] : mov        esi, dword ptr [rax + rsi*4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b195 | 0x0ab195 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:50 |

Source code snippet

```C
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);
    BF_ENC(l, r, s, p[16]);
# if BF_ROUNDS == 20
    BF_ENC(r, l, s, p[17]);
    BF_ENC(l, r, s, p[18]);
    BF_ENC(r, l, s, p[19]);
    BF_ENC(l, r, s, p[20]);

```


Leaking instruction

```
[0xab195] : add        esi, dword ptr [rax + rcx*4 + 0x400]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b1a4 | 0x0ab1a4 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:50 |

Source code snippet

```C
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);
    BF_ENC(l, r, s, p[16]);
# if BF_ROUNDS == 20
    BF_ENC(r, l, s, p[17]);
    BF_ENC(l, r, s, p[18]);
    BF_ENC(r, l, s, p[19]);
    BF_ENC(l, r, s, p[20]);

```


Leaking instruction

```
[0xab1a4] : xor        ecx, dword ptr [rax + rsi*4 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0b1ad | 0x0ab1ad | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:50 |

Source code snippet

```C
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);
    BF_ENC(r, l, s, p[15]);
    BF_ENC(l, r, s, p[16]);
# if BF_ROUNDS == 20
    BF_ENC(r, l, s, p[17]);
    BF_ENC(l, r, s, p[18]);
    BF_ENC(r, l, s, p[19]);
    BF_ENC(l, r, s, p[20]);

```


Leaking instruction

```
[0xab1ad] : add        esi, dword ptr [rax + rdx*4 + 0xc00]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0aff7 | 0x0aaff7 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:43 |

Source code snippet

```C
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);

```


Leaking instruction

```
[0xaaff7] : add        r8d, dword ptr [rax + r9*4 + 0x400]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0aff3 | 0x0aaff3 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:43 |

Source code snippet

```C
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);
    BF_ENC(l, r, s, p[14]);

```


Leaking instruction

```
[0xaaff3] : mov        r8d, dword ptr [rax + r8*4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0afd0 | 0x0aafd0 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:42 |

Source code snippet

```C
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);

```


Leaking instruction

```
[0xaafd0] : add        r8d, dword ptr [rax + r9*4 + 0xc00]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0afc8 | 0x0aafc8 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:42 |

Source code snippet

```C
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);

```


Leaking instruction

```
[0xaafc8] : xor        r8d, dword ptr [rax + rbx*4 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0ae18 | 0x0aae18 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:35 |

Source code snippet

```C
    l = data[0];
    r = data[1];

    l ^= p[0];
    BF_ENC(r, l, s, p[1]);
    BF_ENC(l, r, s, p[2]);
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);

```


Leaking instruction

```
[0xaae18] : add        r8d, dword ptr [rax + rdx*4 + 0x400]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0ae23 | 0x0aae23 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:35 |

Source code snippet

```C
    l = data[0];
    r = data[1];

    l ^= p[0];
    BF_ENC(r, l, s, p[1]);
    BF_ENC(l, r, s, p[2]);
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);

```


Leaking instruction

```
[0xaae23] : xor        edx, dword ptr [rax + rbx*4 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0ae33 | 0x0aae33 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:35 |

Source code snippet

```C
    l = data[0];
    r = data[1];

    l ^= p[0];
    BF_ENC(r, l, s, p[1]);
    BF_ENC(l, r, s, p[2]);
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);

```


Leaking instruction

```
[0xaae33] : add        r8d, dword ptr [rax + rdx*4 + 0xc00]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0ae56 | 0x0aae56 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:36 |

Source code snippet

```C
    r = data[1];

    l ^= p[0];
    BF_ENC(r, l, s, p[1]);
    BF_ENC(l, r, s, p[2]);
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);

```


Leaking instruction

```
[0xaae56] : mov        r8d, dword ptr [rax + r8*4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0ae5a | 0x0aae5a | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:36 |

Source code snippet

```C
    r = data[1];

    l ^= p[0];
    BF_ENC(r, l, s, p[1]);
    BF_ENC(l, r, s, p[2]);
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);

```


Leaking instruction

```
[0xaae5a] : add        r8d, dword ptr [rax + r9*4 + 0x400]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0ae66 | 0x0aae66 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:36 |

Source code snippet

```C
    r = data[1];

    l ^= p[0];
    BF_ENC(r, l, s, p[1]);
    BF_ENC(l, r, s, p[2]);
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);

```


Leaking instruction

```
[0xaae66] : xor        r8d, dword ptr [rax + rbx*4 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0ae6e | 0x0aae6e | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:36 |

Source code snippet

```C
    r = data[1];

    l ^= p[0];
    BF_ENC(r, l, s, p[1]);
    BF_ENC(l, r, s, p[2]);
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);

```


Leaking instruction

```
[0xaae6e] : add        r8d, dword ptr [rax + r9*4 + 0xc00]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0ae91 | 0x0aae91 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:37 |

Source code snippet

```C

    l ^= p[0];
    BF_ENC(r, l, s, p[1]);
    BF_ENC(l, r, s, p[2]);
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);

```


Leaking instruction

```
[0xaae91] : mov        r8d, dword ptr [rax + r8*4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0ae95 | 0x0aae95 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:37 |

Source code snippet

```C

    l ^= p[0];
    BF_ENC(r, l, s, p[1]);
    BF_ENC(l, r, s, p[2]);
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);

```


Leaking instruction

```
[0xaae95] : add        r8d, dword ptr [rax + r9*4 + 0x400]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0aea1 | 0x0aaea1 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:37 |

Source code snippet

```C

    l ^= p[0];
    BF_ENC(r, l, s, p[1]);
    BF_ENC(l, r, s, p[2]);
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);

```


Leaking instruction

```
[0xaaea1] : xor        r8d, dword ptr [rax + rbx*4 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0aea9 | 0x0aaea9 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:37 |

Source code snippet

```C

    l ^= p[0];
    BF_ENC(r, l, s, p[1]);
    BF_ENC(l, r, s, p[2]);
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);

```


Leaking instruction

```
[0xaaea9] : add        r8d, dword ptr [rax + r9*4 + 0xc00]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0aecc | 0x0aaecc | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:38 |

Source code snippet

```C
    l ^= p[0];
    BF_ENC(r, l, s, p[1]);
    BF_ENC(l, r, s, p[2]);
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);

```


Leaking instruction

```
[0xaaecc] : mov        r8d, dword ptr [rax + r8*4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0aed0 | 0x0aaed0 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:38 |

Source code snippet

```C
    l ^= p[0];
    BF_ENC(r, l, s, p[1]);
    BF_ENC(l, r, s, p[2]);
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);

```


Leaking instruction

```
[0xaaed0] : add        r8d, dword ptr [rax + r9*4 + 0x400]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0aedc | 0x0aaedc | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:38 |

Source code snippet

```C
    l ^= p[0];
    BF_ENC(r, l, s, p[1]);
    BF_ENC(l, r, s, p[2]);
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);

```


Leaking instruction

```
[0xaaedc] : xor        r8d, dword ptr [rax + rbx*4 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0aee4 | 0x0aaee4 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:38 |

Source code snippet

```C
    l ^= p[0];
    BF_ENC(r, l, s, p[1]);
    BF_ENC(l, r, s, p[2]);
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);

```


Leaking instruction

```
[0xaaee4] : add        r8d, dword ptr [rax + r9*4 + 0xc00]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0af07 | 0x0aaf07 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:39 |

Source code snippet

```C
    BF_ENC(r, l, s, p[1]);
    BF_ENC(l, r, s, p[2]);
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);

```


Leaking instruction

```
[0xaaf07] : mov        r8d, dword ptr [rax + r8*4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0af0b | 0x0aaf0b | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:39 |

Source code snippet

```C
    BF_ENC(r, l, s, p[1]);
    BF_ENC(l, r, s, p[2]);
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);

```


Leaking instruction

```
[0xaaf0b] : add        r8d, dword ptr [rax + r9*4 + 0x400]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0af17 | 0x0aaf17 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:39 |

Source code snippet

```C
    BF_ENC(r, l, s, p[1]);
    BF_ENC(l, r, s, p[2]);
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);

```


Leaking instruction

```
[0xaaf17] : xor        r8d, dword ptr [rax + rbx*4 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0af1f | 0x0aaf1f | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:39 |

Source code snippet

```C
    BF_ENC(r, l, s, p[1]);
    BF_ENC(l, r, s, p[2]);
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);

```


Leaking instruction

```
[0xaaf1f] : add        r8d, dword ptr [rax + r9*4 + 0xc00]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0af42 | 0x0aaf42 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:40 |

Source code snippet

```C
    BF_ENC(l, r, s, p[2]);
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);

```


Leaking instruction

```
[0xaaf42] : mov        r8d, dword ptr [rax + r8*4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0af46 | 0x0aaf46 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:40 |

Source code snippet

```C
    BF_ENC(l, r, s, p[2]);
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);

```


Leaking instruction

```
[0xaaf46] : add        r8d, dword ptr [rax + r9*4 + 0x400]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0af52 | 0x0aaf52 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:40 |

Source code snippet

```C
    BF_ENC(l, r, s, p[2]);
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);

```


Leaking instruction

```
[0xaaf52] : xor        r8d, dword ptr [rax + rbx*4 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0af5a | 0x0aaf5a | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:40 |

Source code snippet

```C
    BF_ENC(l, r, s, p[2]);
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);

```


Leaking instruction

```
[0xaaf5a] : add        r8d, dword ptr [rax + r9*4 + 0xc00]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0af7d | 0x0aaf7d | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:41 |

Source code snippet

```C
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);

```


Leaking instruction

```
[0xaaf7d] : mov        r8d, dword ptr [rax + r8*4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0af81 | 0x0aaf81 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:41 |

Source code snippet

```C
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);

```


Leaking instruction

```
[0xaaf81] : add        r8d, dword ptr [rax + r9*4 + 0x400]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0af8d | 0x0aaf8d | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:41 |

Source code snippet

```C
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);

```


Leaking instruction

```
[0xaaf8d] : xor        r8d, dword ptr [rax + rbx*4 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0af95 | 0x0aaf95 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:41 |

Source code snippet

```C
    BF_ENC(r, l, s, p[3]);
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);

```


Leaking instruction

```
[0xaaf95] : add        r8d, dword ptr [rax + r9*4 + 0xc00]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0afb8 | 0x0aafb8 | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:42 |

Source code snippet

```C
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);

```


Leaking instruction

```
[0xaafb8] : mov        r8d, dword ptr [rax + r8*4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name   | Object Name      | Source Path                                                   |
|:---------------|:---------|:---------------------------------|:----------|:--------------|:-----------------|:--------------------------------------------------------------|
| 0x7fffb7f0afbc | 0x0aafbc | Secret dep. mem. operation (R/W) | none      | BF_encrypt    | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/bf/bf_enc.c:42 |

Source code snippet

```C
    BF_ENC(l, r, s, p[4]);
    BF_ENC(r, l, s, p[5]);
    BF_ENC(l, r, s, p[6]);
    BF_ENC(r, l, s, p[7]);
    BF_ENC(l, r, s, p[8]);
    BF_ENC(r, l, s, p[9]);
    BF_ENC(l, r, s, p[10]);
    BF_ENC(r, l, s, p[11]);
    BF_ENC(l, r, s, p[12]);
    BF_ENC(r, l, s, p[13]);

```


Leaking instruction

```
[0xaafbc] : add        r8d, dword ptr [rax + r9*4 + 0x400]
```
### Leaks for OPENSSL_hexchar2int

| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name         | Object Name      | Source Path                                                |
|:---------------|:---------|:---------------------------------|:----------|:--------------------|:-----------------|:-----------------------------------------------------------|
| 0x7fffb7fddbc9 | 0x17dbc9 | Secret dep. mem. operation (R/W) | none      | OPENSSL_hexchar2int | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/o_str.c:105 |

Source code snippet

```C
    return l + OPENSSL_strlcpy(dst, src, size);
}

int OPENSSL_hexchar2int(unsigned char c)
{
#ifdef CHARSET_EBCDIC
    c = os_toebcdic[c];
#endif

    switch (c) {

```


Leaking instruction

```
[0x17dbc9] : movsx      eax, byte ptr [rax + rdi]
```
### Leaks for set_hex (or) ASN1_generate_nconf@@OPENSSL_1_1_0

| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name                                     | Object Name   | Source Path                                            |
|:---------------|:---------|:---------------------------------|:----------|:------------------------------------------------|:--------------|:-------------------------------------------------------|
| 0x431cf2       | 0x031cf2 | Secret dep. mem. operation (R/W) | none      | set_hex (or) ASN1_generate_nconf@@OPENSSL_1_1_0 | openssl       | /home/nicolas/cryptolibs/openssl_x86_64/apps/enc.c:616 |

Source code snippet

```C
        j = (unsigned char)*in;
        *(in++) = '\0';
        if (j == 0)
            break;
        if (!isxdigit(j)) {
            BIO_printf(bio_err, "non-hex digit\n");
            return 0;
        }
        j = (unsigned char)OPENSSL_hexchar2int(j);
        if (i & 1)

```


Leaking instruction

```
[0x431cf2] : test       byte ptr [rdx + rax*2 + 1], 0x10
```
