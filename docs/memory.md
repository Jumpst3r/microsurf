# Secret Dependent Memory Accesses

_This page gives an introduction to secret dependent memory accesses, assuming no prior technical knowledge._

## Introduction

Secret dependent memory accesses can lead to side channels which can be used to recover secrets. Commonly, these attacks are possible because reading data from cache is faster than reading data from memory. Past research [1,2] has shown that cache attacks are practical and can be used to compromise cryptographic material.

A classical example of a secret dependent memory access is using the secret (or parts of it) to index a table:


```
int SBOX[256] = {...};
int main(int argc, char **argv){
    int secret = atoi(argv[1]);
    int sub = SBOX[secret];
    return sub
}
```
In the given example, a secret integer is read from a user input and substituted using a table. To retrieve the substited values, the secret is used as an index. While this looks like a toy example, it is important to note that many ciphers (such as AES) are substitution based. Many frameworks revert back to a table-based, leaking implementation on non-mainline architectures. Even on `x86`, some frameworks may choose to leverage a table-based implementation in the absence of crypto or SIMD extensions.

## Secret Dependent Memory Access Detection

In the *Microsurf* framework, secret dependent memory access detection can be implemented with the `DataLeakDetector`  module. Passing this module to the detectio pipeline will flag any observed secret dependent memory accesses:

```
scd = SCDetector(modules=[
        DataLeakDetector(binaryLoader=binLoader),
    ]
    )
scd.exec()
```

## The `DataLeakDetector` module

The exact documentation for the `DataLeakDetector` module is given bellow.

```{eval-rst}
.. autoclass:: microsurf.DataLeakDetector

```

## References

[1] Liu, F., Yarom, Y., Ge, Q., Heiser, G. and Lee, R.B., 2015, May. Last-level cache side-channel attacks are practical. In 2015 IEEE symposium on security and privacy (pp. 605-622). IEEE.

[2] Yarom, Y., Genkin, D. and Heninger, N., 2017. CacheBleed: a timing attack on OpenSSL constant-time RSA. Journal of Cryptographic Engineering, 7(2), pp.99-112.