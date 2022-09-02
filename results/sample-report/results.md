# Microsurf Analysis Results

__Run at__: 09/02/2022, 14:45:59 

__Elapsed time (analysis)__: 00:03:54 

__Elapsed time (single run emulation)__: 0:00:00.238856 

__Total leak count__: 82 

__Binary__: `docs/examples/rootfs/openssl/jail-openssl-1.1.1dev-x8664/openssl`
 >ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 4.4.0, with debug_info, not stripped 

__Args__: `['camellia-128-ecb', '-in', 'input.bin', '-out', 'output.bin', '-nosalt', '-K', '@']` 

__Emulation root__: `docs/examples/rootfs/openssl/jail-openssl-1.1.1dev-x8664/` 

__Table of contents:__

[TOC] 

## Overview by function name
| Symbol Name                                     |   Memory Leak Count |   CF Leak Count |
|:------------------------------------------------|--------------------:|----------------:|
| _x86_64_Camellia_encrypt                        |                  48 |               0 |
| Camellia_Ekeygen                                |                  32 |               0 |
| OPENSSL_hexchar2int                             |                   1 |               0 |
| set_hex (or) ASN1_generate_nconf@@OPENSSL_1_1_0 |                   1 |               0 |

### Leaks for Camellia_Ekeygen

| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37ae1 | 0x0d7ae1 | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:691 |

Source code snippet

```C
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx

```


Leaking instruction

```
[0xd7ae1] : xor        edx, dword ptr [rbp + rsi*8]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37ad0 | 0x0d7ad0 | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:686 |

Source code snippet

```C
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx

```


Leaking instruction

```
[0xd7ad0] : xor        edx, dword ptr [rbp + rsi*8 + 4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37ac3 | 0x0d7ac3 | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:682 |

Source code snippet

```C
	xorl	%r11d,%ebx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	movl	2052(%rbp,%rsi,8),%edx
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx

```


Leaking instruction

```
[0xd7ac3] : mov        ecx, dword ptr [rbp + rdi*8]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37abc | 0x0d7abc | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:681 |

Source code snippet

```C
	xorl	%r10d,%eax
	xorl	%r11d,%ebx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	movl	2052(%rbp,%rsi,8),%edx
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx

```


Leaking instruction

```
[0xd7abc] : mov        edx, dword ptr [rbp + rsi*8 + 0x804]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37a93 | 0x0d7a93 | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:669 |

Source code snippet

```C
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	8(%r14),%ebx
	movl	12(%r14),%eax
	xorl	%edx,%ecx
	rorl	$8,%edx
	xorl	%ecx,%r10d

```


Leaking instruction

```
[0xd7a93] : xor        ecx, dword ptr [rbp + rdi*8 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37a8c | 0x0d7a8c | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:668 |

Source code snippet

```C
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	8(%r14),%ebx
	movl	12(%r14),%eax
	xorl	%edx,%ecx
	rorl	$8,%edx

```


Leaking instruction

```
[0xd7a8c] : xor        edx, dword ptr [rbp + rsi*8 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37a7f | 0x0d7a7f | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:665 |

Source code snippet

```C
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	8(%r14),%ebx

```


Leaking instruction

```
[0xd7a7f] : xor        ecx, dword ptr [rbp + rdi*8 + 0x804]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37a7b | 0x0d7a7b | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:664 |

Source code snippet

```C
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx

```


Leaking instruction

```
[0xd7a7b] : xor        edx, dword ptr [rbp + rsi*8]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37a71 | 0x0d7a71 | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:661 |

Source code snippet

```C
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi

```


Leaking instruction

```
[0xd7a71] : xor        ecx, dword ptr [rbp + rdi*8 + 4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37a6a | 0x0d7a6a | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:659 |

Source code snippet

```C
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx

```


Leaking instruction

```
[0xd7a6a] : xor        edx, dword ptr [rbp + rsi*8 + 4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37a5d | 0x0d7a5d | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:655 |

Source code snippet

```C
	xorl	%r9d,%ebx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	movl	2052(%rbp,%rsi,8),%edx
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx

```


Leaking instruction

```
[0xd7a5d] : mov        ecx, dword ptr [rbp + rdi*8]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37a56 | 0x0d7a56 | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:654 |

Source code snippet

```C
	xorl	%r8d,%eax
	xorl	%r9d,%ebx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	movl	2052(%rbp,%rsi,8),%edx
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx

```


Leaking instruction

```
[0xd7a56] : mov        edx, dword ptr [rbp + rsi*8 + 0x804]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37ad7 | 0x0d7ad7 | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:688 |

Source code snippet

```C
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi

```


Leaking instruction

```
[0xd7ad7] : xor        ecx, dword ptr [rbp + rdi*8 + 4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37ae5 | 0x0d7ae5 | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:692 |

Source code snippet

```C
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	16(%r14),%ebx

```


Leaking instruction

```
[0xd7ae5] : xor        ecx, dword ptr [rbp + rdi*8 + 0x804]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37af2 | 0x0d7af2 | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:695 |

Source code snippet

```C
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	16(%r14),%ebx
	movl	20(%r14),%eax
	xorl	%edx,%ecx
	rorl	$8,%edx

```


Leaking instruction

```
[0xd7af2] : xor        edx, dword ptr [rbp + rsi*8 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37bce | 0x0d7bce | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:753 |

Source code snippet

```C
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	32(%r14),%ebx
	movl	36(%r14),%eax
	xorl	%edx,%ecx
	rorl	$8,%edx

```


Leaking instruction

```
[0xd7bce] : xor        edx, dword ptr [rbp + rsi*8 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37bc1 | 0x0d7bc1 | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:750 |

Source code snippet

```C
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	32(%r14),%ebx

```


Leaking instruction

```
[0xd7bc1] : xor        ecx, dword ptr [rbp + rdi*8 + 0x804]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37bbd | 0x0d7bbd | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:749 |

Source code snippet

```C
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx

```


Leaking instruction

```
[0xd7bbd] : xor        edx, dword ptr [rbp + rsi*8]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37bb3 | 0x0d7bb3 | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:746 |

Source code snippet

```C
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi

```


Leaking instruction

```
[0xd7bb3] : xor        ecx, dword ptr [rbp + rdi*8 + 4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37bac | 0x0d7bac | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:744 |

Source code snippet

```C
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx

```


Leaking instruction

```
[0xd7bac] : xor        edx, dword ptr [rbp + rsi*8 + 4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37b9f | 0x0d7b9f | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:740 |

Source code snippet

```C
	xorl	%r11d,%ebx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	movl	2052(%rbp,%rsi,8),%edx
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx

```


Leaking instruction

```
[0xd7b9f] : mov        ecx, dword ptr [rbp + rdi*8]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37b98 | 0x0d7b98 | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:739 |

Source code snippet

```C
	xorl	%r10d,%eax
	xorl	%r11d,%ebx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	movl	2052(%rbp,%rsi,8),%edx
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx

```


Leaking instruction

```
[0xd7b98] : mov        edx, dword ptr [rbp + rsi*8 + 0x804]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37b6f | 0x0d7b6f | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:727 |

Source code snippet

```C
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	24(%r14),%ebx
	movl	28(%r14),%eax
	xorl	%edx,%ecx
	rorl	$8,%edx
	xorl	%ecx,%r10d

```


Leaking instruction

```
[0xd7b6f] : xor        ecx, dword ptr [rbp + rdi*8 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37b68 | 0x0d7b68 | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:726 |

Source code snippet

```C
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	24(%r14),%ebx
	movl	28(%r14),%eax
	xorl	%edx,%ecx
	rorl	$8,%edx

```


Leaking instruction

```
[0xd7b68] : xor        edx, dword ptr [rbp + rsi*8 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37b5b | 0x0d7b5b | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:723 |

Source code snippet

```C
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	24(%r14),%ebx

```


Leaking instruction

```
[0xd7b5b] : xor        ecx, dword ptr [rbp + rdi*8 + 0x804]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37b57 | 0x0d7b57 | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:722 |

Source code snippet

```C
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx

```


Leaking instruction

```
[0xd7b57] : xor        edx, dword ptr [rbp + rsi*8]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37b4d | 0x0d7b4d | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:719 |

Source code snippet

```C
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi

```


Leaking instruction

```
[0xd7b4d] : xor        ecx, dword ptr [rbp + rdi*8 + 4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37b46 | 0x0d7b46 | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:717 |

Source code snippet

```C
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx

```


Leaking instruction

```
[0xd7b46] : xor        edx, dword ptr [rbp + rsi*8 + 4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37b39 | 0x0d7b39 | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:713 |

Source code snippet

```C
	xorl	%r9d,%ebx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	movl	2052(%rbp,%rsi,8),%edx
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx

```


Leaking instruction

```
[0xd7b39] : mov        ecx, dword ptr [rbp + rdi*8]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37b32 | 0x0d7b32 | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:712 |

Source code snippet

```C
	xorl	%r8d,%eax
	xorl	%r9d,%ebx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	movl	2052(%rbp,%rsi,8),%edx
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx

```


Leaking instruction

```
[0xd7b32] : mov        edx, dword ptr [rbp + rsi*8 + 0x804]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37af9 | 0x0d7af9 | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:696 |

Source code snippet

```C
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	16(%r14),%ebx
	movl	20(%r14),%eax
	xorl	%edx,%ecx
	rorl	$8,%edx
	xorl	%ecx,%r8d

```


Leaking instruction

```
[0xd7af9] : xor        ecx, dword ptr [rbp + rdi*8 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name      | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-----------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37bd5 | 0x0d7bd5 | Secret dep. mem. operation (R/W) | none      | Camellia_Ekeygen | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:754 |

Source code snippet

```C
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	32(%r14),%ebx
	movl	36(%r14),%eax
	xorl	%edx,%ecx
	rorl	$8,%edx
	xorl	%ecx,%r8d

```


Leaking instruction

```
[0xd7bd5] : xor        ecx, dword ptr [rbp + rdi*8 + 0x800]
```
### Leaks for _x86_64_Camellia_encrypt

| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f375bf | 0x0d75bf | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:249 |

Source code snippet

```C
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	64(%r14),%ebx
	movl	68(%r14),%eax
	xorl	%edx,%ecx
	rorl	$8,%edx
	xorl	%ecx,%r8d

```


Leaking instruction

```
[0xd75bf] : xor        ecx, dword ptr [rbp + rdi*8 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f375b8 | 0x0d75b8 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:248 |

Source code snippet

```C
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	64(%r14),%ebx
	movl	68(%r14),%eax
	xorl	%edx,%ecx
	rorl	$8,%edx

```


Leaking instruction

```
[0xd75b8] : xor        edx, dword ptr [rbp + rsi*8 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f375ab | 0x0d75ab | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:245 |

Source code snippet

```C
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	64(%r14),%ebx

```


Leaking instruction

```
[0xd75ab] : xor        ecx, dword ptr [rbp + rdi*8 + 0x804]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f375a7 | 0x0d75a7 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:244 |

Source code snippet

```C
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx

```


Leaking instruction

```
[0xd75a7] : xor        edx, dword ptr [rbp + rsi*8]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f3759d | 0x0d759d | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:241 |

Source code snippet

```C
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi

```


Leaking instruction

```
[0xd759d] : xor        ecx, dword ptr [rbp + rdi*8 + 4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37596 | 0x0d7596 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:239 |

Source code snippet

```C
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx

```


Leaking instruction

```
[0xd7596] : xor        edx, dword ptr [rbp + rsi*8 + 4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                              |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:-------------------------------------------------------------------------|
| 0x7fffb7f37384 | 0x0d7384 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:99 |

Source code snippet

```C
	xorl	%r8d,%eax
	xorl	%r9d,%ebx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	movl	2052(%rbp,%rsi,8),%edx
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx

```


Leaking instruction

```
[0xd7384] : mov        edx, dword ptr [rbp + rsi*8 + 0x804]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37589 | 0x0d7589 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:235 |

Source code snippet

```C
	xorl	%r11d,%ebx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	movl	2052(%rbp,%rsi,8),%edx
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx

```


Leaking instruction

```
[0xd7589] : mov        ecx, dword ptr [rbp + rdi*8]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37582 | 0x0d7582 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:234 |

Source code snippet

```C
	xorl	%r10d,%eax
	xorl	%r11d,%ebx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	movl	2052(%rbp,%rsi,8),%edx
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx

```


Leaking instruction

```
[0xd7582] : mov        edx, dword ptr [rbp + rsi*8 + 0x804]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37559 | 0x0d7559 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:222 |

Source code snippet

```C
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	56(%r14),%ebx
	movl	60(%r14),%eax
	xorl	%edx,%ecx
	rorl	$8,%edx
	xorl	%ecx,%r10d

```


Leaking instruction

```
[0xd7559] : xor        ecx, dword ptr [rbp + rdi*8 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37552 | 0x0d7552 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:221 |

Source code snippet

```C
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	56(%r14),%ebx
	movl	60(%r14),%eax
	xorl	%edx,%ecx
	rorl	$8,%edx

```


Leaking instruction

```
[0xd7552] : xor        edx, dword ptr [rbp + rsi*8 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37457 | 0x0d7457 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:154 |

Source code snippet

```C
	xorl	%r9d,%ebx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	movl	2052(%rbp,%rsi,8),%edx
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx

```


Leaking instruction

```
[0xd7457] : mov        ecx, dword ptr [rbp + rdi*8]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37450 | 0x0d7450 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:153 |

Source code snippet

```C
	xorl	%r8d,%eax
	xorl	%r9d,%ebx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	movl	2052(%rbp,%rsi,8),%edx
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx

```


Leaking instruction

```
[0xd7450] : mov        edx, dword ptr [rbp + rsi*8 + 0x804]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37427 | 0x0d7427 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:141 |

Source code snippet

```C
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	32(%r14),%ebx
	movl	36(%r14),%eax
	xorl	%edx,%ecx
	rorl	$8,%edx
	xorl	%ecx,%r8d

```


Leaking instruction

```
[0xd7427] : xor        ecx, dword ptr [rbp + rdi*8 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37420 | 0x0d7420 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:140 |

Source code snippet

```C
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	32(%r14),%ebx
	movl	36(%r14),%eax
	xorl	%edx,%ecx
	rorl	$8,%edx

```


Leaking instruction

```
[0xd7420] : xor        edx, dword ptr [rbp + rsi*8 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37413 | 0x0d7413 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:137 |

Source code snippet

```C
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	32(%r14),%ebx

```


Leaking instruction

```
[0xd7413] : xor        ecx, dword ptr [rbp + rdi*8 + 0x804]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f3740f | 0x0d740f | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:136 |

Source code snippet

```C
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx

```


Leaking instruction

```
[0xd740f] : xor        edx, dword ptr [rbp + rsi*8]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37405 | 0x0d7405 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:133 |

Source code snippet

```C
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi

```


Leaking instruction

```
[0xd7405] : xor        ecx, dword ptr [rbp + rdi*8 + 4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f373fe | 0x0d73fe | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:131 |

Source code snippet

```C
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx

```


Leaking instruction

```
[0xd73fe] : xor        edx, dword ptr [rbp + rsi*8 + 4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f373f1 | 0x0d73f1 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:127 |

Source code snippet

```C
	xorl	%r11d,%ebx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	movl	2052(%rbp,%rsi,8),%edx
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx

```


Leaking instruction

```
[0xd73f1] : mov        ecx, dword ptr [rbp + rdi*8]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f373ea | 0x0d73ea | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:126 |

Source code snippet

```C
	xorl	%r10d,%eax
	xorl	%r11d,%ebx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	movl	2052(%rbp,%rsi,8),%edx
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx

```


Leaking instruction

```
[0xd73ea] : mov        edx, dword ptr [rbp + rsi*8 + 0x804]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f373c1 | 0x0d73c1 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:114 |

Source code snippet

```C
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	24(%r14),%ebx
	movl	28(%r14),%eax
	xorl	%edx,%ecx
	rorl	$8,%edx
	xorl	%ecx,%r10d

```


Leaking instruction

```
[0xd73c1] : xor        ecx, dword ptr [rbp + rdi*8 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f373ba | 0x0d73ba | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:113 |

Source code snippet

```C
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	24(%r14),%ebx
	movl	28(%r14),%eax
	xorl	%edx,%ecx
	rorl	$8,%edx

```


Leaking instruction

```
[0xd73ba] : xor        edx, dword ptr [rbp + rsi*8 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f373ad | 0x0d73ad | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:110 |

Source code snippet

```C
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	24(%r14),%ebx

```


Leaking instruction

```
[0xd73ad] : xor        ecx, dword ptr [rbp + rdi*8 + 0x804]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f373a9 | 0x0d73a9 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:109 |

Source code snippet

```C
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx

```


Leaking instruction

```
[0xd73a9] : xor        edx, dword ptr [rbp + rsi*8]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f3739f | 0x0d739f | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:106 |

Source code snippet

```C
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi

```


Leaking instruction

```
[0xd739f] : xor        ecx, dword ptr [rbp + rdi*8 + 4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37398 | 0x0d7398 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:104 |

Source code snippet

```C
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx

```


Leaking instruction

```
[0xd7398] : xor        edx, dword ptr [rbp + rsi*8 + 4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f3738b | 0x0d738b | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:100 |

Source code snippet

```C
	xorl	%r9d,%ebx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	movl	2052(%rbp,%rsi,8),%edx
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx

```


Leaking instruction

```
[0xd738b] : mov        ecx, dword ptr [rbp + rdi*8]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37464 | 0x0d7464 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:158 |

Source code snippet

```C
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx

```


Leaking instruction

```
[0xd7464] : xor        edx, dword ptr [rbp + rsi*8 + 4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f3746b | 0x0d746b | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:160 |

Source code snippet

```C
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi

```


Leaking instruction

```
[0xd746b] : xor        ecx, dword ptr [rbp + rdi*8 + 4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37475 | 0x0d7475 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:163 |

Source code snippet

```C
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx

```


Leaking instruction

```
[0xd7475] : xor        edx, dword ptr [rbp + rsi*8]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f374ec | 0x0d74ec | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:194 |

Source code snippet

```C
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	48(%r14),%ebx
	movl	52(%r14),%eax
	xorl	%edx,%ecx
	rorl	$8,%edx

```


Leaking instruction

```
[0xd74ec] : xor        edx, dword ptr [rbp + rsi*8 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37545 | 0x0d7545 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:218 |

Source code snippet

```C
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	56(%r14),%ebx

```


Leaking instruction

```
[0xd7545] : xor        ecx, dword ptr [rbp + rdi*8 + 0x804]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37541 | 0x0d7541 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:217 |

Source code snippet

```C
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx

```


Leaking instruction

```
[0xd7541] : xor        edx, dword ptr [rbp + rsi*8]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37537 | 0x0d7537 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:214 |

Source code snippet

```C
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi

```


Leaking instruction

```
[0xd7537] : xor        ecx, dword ptr [rbp + rdi*8 + 4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37530 | 0x0d7530 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:212 |

Source code snippet

```C
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx

```


Leaking instruction

```
[0xd7530] : xor        edx, dword ptr [rbp + rsi*8 + 4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37523 | 0x0d7523 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:208 |

Source code snippet

```C
	xorl	%r9d,%ebx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	movl	2052(%rbp,%rsi,8),%edx
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx

```


Leaking instruction

```
[0xd7523] : mov        ecx, dword ptr [rbp + rdi*8]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f3751c | 0x0d751c | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:207 |

Source code snippet

```C
	xorl	%r8d,%eax
	xorl	%r9d,%ebx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	movl	2052(%rbp,%rsi,8),%edx
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx

```


Leaking instruction

```
[0xd751c] : mov        edx, dword ptr [rbp + rsi*8 + 0x804]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f374f3 | 0x0d74f3 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:195 |

Source code snippet

```C
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	48(%r14),%ebx
	movl	52(%r14),%eax
	xorl	%edx,%ecx
	rorl	$8,%edx
	xorl	%ecx,%r8d

```


Leaking instruction

```
[0xd74f3] : xor        ecx, dword ptr [rbp + rdi*8 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f374df | 0x0d74df | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:191 |

Source code snippet

```C
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	48(%r14),%ebx

```


Leaking instruction

```
[0xd74df] : xor        ecx, dword ptr [rbp + rdi*8 + 0x804]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37479 | 0x0d7479 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:164 |

Source code snippet

```C
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	40(%r14),%ebx

```


Leaking instruction

```
[0xd7479] : xor        ecx, dword ptr [rbp + rdi*8 + 0x804]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f374db | 0x0d74db | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:190 |

Source code snippet

```C
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx

```


Leaking instruction

```
[0xd74db] : xor        edx, dword ptr [rbp + rsi*8]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f374d1 | 0x0d74d1 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:187 |

Source code snippet

```C
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi

```


Leaking instruction

```
[0xd74d1] : xor        ecx, dword ptr [rbp + rdi*8 + 4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f374ca | 0x0d74ca | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:185 |

Source code snippet

```C
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx
	xorl	4(%rbp,%rdi,8),%ecx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	xorl	0(%rbp,%rsi,8),%edx

```


Leaking instruction

```
[0xd74ca] : xor        edx, dword ptr [rbp + rsi*8 + 4]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f374bd | 0x0d74bd | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:181 |

Source code snippet

```C
	xorl	%r11d,%ebx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	movl	2052(%rbp,%rsi,8),%edx
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx
	shrl	$16,%ebx

```


Leaking instruction

```
[0xd74bd] : mov        ecx, dword ptr [rbp + rdi*8]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f374b6 | 0x0d74b6 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:180 |

Source code snippet

```C
	xorl	%r10d,%eax
	xorl	%r11d,%ebx
	movzbl	%ah,%esi
	movzbl	%bl,%edi
	movl	2052(%rbp,%rsi,8),%edx
	movl	0(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	shrl	$16,%eax
	movzbl	%bh,%edi
	xorl	4(%rbp,%rsi,8),%edx

```


Leaking instruction

```
[0xd74b6] : mov        edx, dword ptr [rbp + rsi*8 + 0x804]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f3748d | 0x0d748d | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:168 |

Source code snippet

```C
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	40(%r14),%ebx
	movl	44(%r14),%eax
	xorl	%edx,%ecx
	rorl	$8,%edx
	xorl	%ecx,%r10d

```


Leaking instruction

```
[0xd748d] : xor        ecx, dword ptr [rbp + rdi*8 + 0x800]
```
| Runtime Addr   | offset   | Detection Module                 | Comment   | Symbol Name              | Object Name      | Source Path                                                               |
|:---------------|:---------|:---------------------------------|:----------|:-------------------------|:-----------------|:--------------------------------------------------------------------------|
| 0x7fffb7f37486 | 0x0d7486 | Secret dep. mem. operation (R/W) | none      | _x86_64_Camellia_encrypt | libcrypto.so.1.1 | /home/nicolas/cryptolibs/openssl_x86_64/crypto/camellia/cmll-x86_64.s:167 |

Source code snippet

```C
	xorl	0(%rbp,%rsi,8),%edx
	xorl	2052(%rbp,%rdi,8),%ecx
	movzbl	%al,%esi
	movzbl	%bh,%edi
	xorl	2048(%rbp,%rsi,8),%edx
	xorl	2048(%rbp,%rdi,8),%ecx
	movl	40(%r14),%ebx
	movl	44(%r14),%eax
	xorl	%edx,%ecx
	rorl	$8,%edx

```


Leaking instruction

```
[0xd7486] : xor        edx, dword ptr [rbp + rsi*8 + 0x800]
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
