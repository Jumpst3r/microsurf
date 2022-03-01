A simple C example featuring:

non-deterministic branching:

```
if (branch > 50){
    ...
```

A secret dependent, non-deterministic memory access in the non-deterministic branch:

```
val = T[secret + (branch % 20)];
```

A non deterministic, non-secret dependent memory access:

```
val2 = M[branch];
```

The `atoi()` function also induces several secret dependent accesses.

The following adresses are secret dependent (`secret-x86-32.bin`):

- `0x8051920`: `lea    eax,[edx-0x30]` in `___strtol_l_internal`, called by `atoi()`
- `0x805190f`: `movzx edx, byte ptr [eax + 1]` in `___strtol_l_internal`, called by `atoi()`
- `0x8051913`: `lea ecx, [eax + 1]` in `___strtol_l_internal`, called by `atoi()`
- `0x8049822`: `mov ecx, dword ptr [ebp - 0x44]` in `main()` (`val = T[secret + (branch % 20)];`)
- `0x8049822`: `mov ecx, dword ptr [ebp - 0x44]` in `main()` (`val = T[secret + (branch % 20)];`)
- `0x804984f`: `lea edx, [eax*4]` in `main()` (`val = T[secret + (branch % 20)];`)
- `0x8049856`: `mov eax, dword ptr [ebp - 0x50]` in `main()` (`val = T[secret + (branch % 20)];`)
- `0x804985b`: `mov eax, dword ptr [eax]` in `main()` (`val = T[secret + (branch % 20)];`)