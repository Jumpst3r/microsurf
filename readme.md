<img align="left" width="60" height="60" src="doc/logo.png" alt="Resume application project app icon">


# MicroSurf: An architecture independent side channel detection framework
[![tests](https://github.com/Jumpst3r/msc-thesis-work/actions/workflows/pytest.yml/badge.svg?branch=main)](https://github.com/Jumpst3r/msc-thesis-work/actions/workflows/pytest.yml)

We have a title + a silly logo now

## Usage examples 

Documentation can be found [here](USAGE.pdf)

Usage examples:

- [openssl-camellia128](doc/examples/openssl-camellia-128.py)

## Installation

1. Create a virtualenv & activate it:

```
virtualenv env
source env/bin/activate
```

2. Install the package locally:

```
pip install -e .
```


## Tests 

(`pip install -r requirements_dev.txt`)

- Unit / Integration tests: `pytest`
- Type checking: `mypy src`
- Linting: `flake8 src`

