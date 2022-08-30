# Compiler-induced Constant Time Violations

## Introduction

Mainstream compiler were not build to enforce constant time proprieties, they are meant to provide the best possible performance. This is not always compatible with constant time proprieties.

To complicate things further: If a binary is formally proven to be leakage free with one compiler on one architecture, then this cannot be extrapolated to other architectures, compilers or even compiler versions.

For an extensive study on compiler-induced behavior, consult [1].

## Examples

### Function inlining

Inlining is an optimization which removes the overhead of creating and destroying function frames by embedding (small-ish) functions into the caller.

By doing so, the compiler may inadvertently introduce a secret dependent jump.


## References

[1] Simon, L., Chisnall, D. and Anderson, R., 2018, April. What you get is what you C: Controlling side effects in mainstream C compilers. In 2018 IEEE European Symposium on Security and Privacy (EuroS&P) (pp. 1-15). IEEE.