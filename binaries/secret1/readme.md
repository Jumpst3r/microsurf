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

- `0x805190f`: `movzx edx, byte ptr [eax + 1]` in `___strtol_l_internal`, called by `atoi()`
- `0x804985b`: `mov eax, dword ptr [eax]` in `main()` (`val = T[secret + (branch % 20)];`)