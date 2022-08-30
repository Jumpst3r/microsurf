# Secret Dependent Control Flow

_This page gives an introduction to secret dependent control flow, assuming no prior technical knowledge._

## Introduction

Secret-dependent control-flow is a possible source of variable execution time. This can be exploited through timing attacks. Note that not all secret dependent control flow operation lead to exploitable timing differences: This depends on the resolution available to the attacker.

Secret dependent control flow operations should be eliminated from high-level code, as timing attacks are practical [1,2] and can compromise cryptographic material in a remote setting.

Classical examples of secret dependent control flow include (but are not limited to):

- Secret dependent branching (for example the conditional subtraction in a naive [Montgomery](https://en.wikipedia.org/wiki/Montgomery_modular_multiplication) modular multiplication )
- Secret dependent loop iterations: These have also been shown to produce secret dependent execution timing. Brumley et al. [2] discovered a secret dependent iteration count in the Montgomery ladder primitive used to perform scalar multiplication in OpenSSL `0.9.8o`. 


```{warning}
secret dependent control flow has also been shown to be caused by certain compiler [optimizations](compiler.md).
```


## Secret Dependent Control Flow Detection

In the *Microsurf* framework, secret dependent control flow detection can be implemented with the `CFLeakDetector`  module. Passing this module to the detectio pipeline will flag any observed secret dependent control flow operations:

```
scd = SCDetector(modules=[
        DataLeakDetector(binaryLoader=binLoader),
    ]
    )
scd.exec()
```

## The `CFLeakDetector` module

The exact documentation for the `CFLeakDetector` module is given bellow.

```{eval-rst}
.. autoclass:: microsurf.CFLeakDetector

```

## References

[1] Brumley, D. and Boneh, D., 2005. Remote timing attacks are practical. Computer Networks, 48(5), pp.701-716.

[2] Brumley, B.B. and Tuveri, N., 2011, September. Remote timing attacks are still practical. In European Symposium on Research in Computer Security (pp. 355-371). Springer, Berlin, Heidelberg.