<img align="left" width="60" height="60" src="doc/figures/logo.png" alt="application project app icon">


## Microsurf: An architecture independent side channel detection framework


Microsurf is a framework for finding side channel vulnerabilities in compiled binaries. It features:

- Cross-architecture support (`i386`, `x86_64`, `arm32`, `arm64`)
- Leverages machine learning to 

### Usage examples 

Documentation can be found [here](USAGE.pdf)

Usage examples:

- [openssl-camellia128](doc/examples/openssl-camellia-128.py)

### Installation

1. Create a virtualenv & activate it:

```
virtualenv env
source env/bin/activate
```

2. Install the package locally:

```
pip install -e .
```
