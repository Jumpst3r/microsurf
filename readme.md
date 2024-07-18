# Microsurf

### About

***Microsurf*** is a framework for finding side channel vulnerabilities in compiled binaries. It features:


- **Cross-architecture** support (tested on `i386`, `x86_64`, `arm32`, `arm64`, `riscv`, `mips`)
- **No source code required** - black-box testing and analysis
- Human-readable **markdown reports**, parsable **json reports** or directly as pandas **dataframes**
- Forced deterministic execution by hooking sources of randomness (**less false positives**)
- **Easy to use**. Provides a high level API for developers and users alike
- **Fast.** Optimized for parallel execution

### Quickstart

Install the framework (requires python 3.9 or 3.10):

```
pip install .
```

Run the example:

```
python docs/examples/openssl.py
```

### Sample Report:

A sample markdown report can be consulted [here](results/sample-report/results.md).

### Examples

Analyzing a binary is simple: You first begin by creating a `BinaryLoader` object, which tells where the target is and how it should be emulated:

```python
# the arguments to pass to the binary.
# the secret is marked with a '@' placeholder
opensslArgs = [
    "camellia-128-ecb",
    "-e",
    "-in",
    "input.bin",
    "-out",
    "output.bin",
    "-nosalt",
    "-K",
    "@",
]

# list of objects to trace
sharedObjects = ['libcrypto']

binLoader = BinaryLoader(
    path=binpath,
    args=opensslArgs,
    # emulation root directory
    rootfs=jailroot,
    # openssl_hex_key_generator generates hex secrets, these will replace the
    # @ symbol in the arg list during emulation.
    rndGen=openssl_hex_key_generator(keylen=128, nbTraces=10),
    sharedObjects=sharedObjects
)
if binaryLoader.configure(): # something went wrong
```

Now all that remains is to create an `SCDetector` object and pass any required detection modules. Calling the `.exec()` function will run the analysis.

```python
scd = SCDetector(modules=[
        # Secret dependent memory read detection
        DataLeakDetector(binaryLoader=binLoader),
        # Secret dependent control flow detection
        CFLeakDetector(binaryLoader=binLoader),
    ])
# Run the analysis
scd.exec()
```

The results will be saved to disk in Markdown format.

### Documentation

Documentation can be found [here](USAGE.pdf).

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

### Contributing

Contributions are very welcome and actively encouraged.

### Evaluation Scripts

The scripts used for evaluating different frameworks are stored in the `eval-scripts` directory.

### License

This is free software distributed under the [MIT License](LICENSE).
