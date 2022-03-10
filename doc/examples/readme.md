# Examples

This folder contains an example on how to use the microsurf library against openssl.

## Results openssl-camilla-128


Run at 10.03.22 - 15:26

| Offset   | Instruction                             | Function              | Lib              | Leakage model | MI score |
|----------|-----------------------------------------|-----------------------|------------------|---------------|----------|
| 0x95592  | `xor    edx,DWORD PTR [ebp+esi*8+0x4]`    | `_x86_Camellia_encrypt` | libcrypto.so.1.1 | Hamming       | 0.12     |
| 0x9571e  | `xor    eax,DWORD PTR [ebp+esi*8+0x804]`  | `_x86_Camellia_encrypt` | libcrypto.so.1.1 | Hamming       | 0.14     |
| 0x95768  | `xor    edx,DWORD PTR [ebp+eax*8+0x800]`  | `_x86_Camellia_encrypt` | libcrypto.so.1.1 | Hamming       | 0.21     |
| 0x9577b  | `xor    ecx,DWORD PTR [ebp+esi*8+0x800]`  | `_x86_Camellia_encrypt` | libcrypto.so.1.1 | Hamming       | 0.15     |
| 0x95d5e  | `xor    edx,DWORD PTR [ebp+esi*8+0x0]`    | `Camellia_Ekeygen`      | libcrypto.so.1.1 | Hamming       | 0.14     |
| 0x95dba  | `xor    ebx,DWORD PTR [ebp+esi*8+0x4]`    | `Camellia_Ekeygen`      | libcrypto.so.1.1 | Hamming       | 0.14     |
| 0x95e5f  | `xor    edx,DWORD PTR [ebp+esi*8+0x0]`    | `Camellia_Ekeygen`      | libcrypto.so.1.1 | Hamming       | 0.13     |
| 0x95ebb  | `xor    ebx,DWORD PTR [ebp+esi*8+0x4]`    | `Camellia_Ekeygen`      | libcrypto.so.1.1 | Hamming       | 0.29     |
| 0x95edd  | `xor    ebx,DWORD PTR [ebp+ecx*8+0x800]`  | `Camellia_Ekeygen`      | libcrypto.so.1.1 | Hamming       | 0.14     |
| 0x95ef0  | `xor    eax,DWORD PTR [ebp+esi*8+0x800]`  | `Camellia_Ekeygen`      | libcrypto.so.1.1 | Hamming       | 0.11     |
| 0x13f5cf | `movsx  edx,BYTE PTR [ecx+eax*1-0xbd5e0]` | `OPENSSL_hexchar2int`   | libcrypto.so.1.1 | Hamming       |          |

The DATA paper also includes an experiment against camilla-128 and they report the following data leaks:

- `Camellia_Ekeygen`
- `x86_64_Camellia encrypt`
- `OPENSSL_hexchar2int`
- `set_hex` (leak caused by calling libc's `isxdigit`)

Conclusion: With the exception of `set_hex` we seem to detect the same secret dependent memory accesses.

*TODO*:

- Profile runtime / RAM usage
- Experiment with different leakage models (the DATA paper reports a higher number of total leakages in these functions. Leakages with bad MI scores get filtered and the MI score depends on the leakage model so..)