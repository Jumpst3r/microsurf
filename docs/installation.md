# Installation

*tentative ! eventually the package should be published to pypi at release. The repository will probably have to be renamed too.*

## Requirements

Microsurf has been tested on python 3.9 and python 3.6. It might work on other python version. If you want to install the package in a virtual environment, you will need a tool that allows you to do so:

```bash
pip3 install virtualenv
```

## Installing microsurf

1. Clone the repository:

```bash
git clone https://github.com/Jumpst3r/msc-thesis-work.git
cd msc-thesis-work
```

2. Create a virtual environment (optional, highly recommended)

```
virtualenv env
source env/bin/activate
```

3. Install the microsurf package:

```
pip install -e .
```

```{note}
This installs the framework in *editable* mode, meaning you can edit the source code without having to reinstall it after making changes.
```
