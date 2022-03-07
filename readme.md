<img align="left" width="60" height="60" src="doc/logo.png" alt="Resume application project app icon">


# MicroSurf: An architecture independent side channel detection framework
[![tests](https://github.com/Jumpst3r/msc-thesis-work/actions/workflows/pytest.yml/badge.svg?branch=main)](https://github.com/Jumpst3r/msc-thesis-work/actions/workflows/pytest.yml)

We have a title + a silly logo now

# Quickstart

1. Create a virtualenv & activate it:

```
virtualenv env
source env/bin/activate
```

2. Install the package locally:

```
pip install -e .
```

2. Run a sample:

```
python -m microsurf --binary test/binaries/secret1/secret-x86-64.bin --sc data
```

# Tests 

- Unit / Integration tests: `pytest`
- Type checking: `mypy src`
- Linting: `flake8 src`

