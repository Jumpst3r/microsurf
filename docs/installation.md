# Installation

*tentative ! eventually the package should be published to pypi at release. The repository will probably have to be renamed too.*

### Requirements

Microsurf has been tested on python 3.9 and python 3.10. It might work on other python version, check your version with

```
python --version
```

If your python version differs, follow [this](https://computingforgeeks.com/how-to-install-python-on-ubuntu-linux-system/) guide to install the required version. 

If you want to install the package in a virtual environment, you will need a tool that allows you to do so:

```bash
pip3 install virtualenv
```

The framework has been tested with Ubuntu 22.04 LTS x86-64. It has not been tested on M1 (ARM) chips.

### Installing microsurf (from source)

1. Acquire the repository:

If the code was acquired as a zip archive:

```bash
unzip -r microsurf.zip
cd microsurf
```

If access has been granted to repository or the repository has been made public:

```bash
git clone https://github.com/Jumpst3r/microsurf.git
cd microsurf
```

2. Create a virtual environment (optional, highly recommended)

Using the default python version:
```
virtualenv env
source env/bin/activate
```

Using a custom interpreter path:
```
virtualenv --python=/usr/bin/python3.9  env
```

3. Install the microsurf package:

```
pip install -e .
```

```{note}
This installs the framework in *editable* mode, meaning you can edit the source code without having to reinstall it after making changes.
```
