# Secret Generators

_This page describes how secrets are generated for use with the Microsurf framework._

## Introduction

Cryptographic frameworks expect secrets in various different formats. Sometimes they can be directly passed has hexadecimal strings in a command line argument list. Sometimes a utility will expect a path to a file containing the secret in a binary format.

Microsurf is designed to acomodate both cases. Secret generators are classes which produce a specific secret, either to be included directly in a list of command line arguments or to be written to a file. The path to the file will then be passed as a command line arguments.

## Existing Generators

A number of common cases are covered with predefined secret generators. This section documents the classes.

```{eval-rst}
.. autoclass:: microsurf.utils.generators.RSAPrivKeyGenerator
```
```{eval-rst}
.. autoclass:: microsurf.utils.generators.DSAPrivateKeyGenerator
```

```{eval-rst}
.. autoclass:: microsurf.utils.generators.ECDSAPrivateKeyGenerator
```

```{eval-rst}
.. autoclass:: microsurf.utils.generators.hex_key_generator
```


## Writing your own secret generator

What if the primitive you wish to evaluate expects a different format ? Worry not, as you can implement your own secret generator to acomodate your needs.

```{eval-rst}
.. autoclass:: microsurf.utils.generators.SecretGenerator
   :members: __call__, getSecret
```

In order to write a custom secret generator you must choose one of two operational modes:

1. Directly including the encoded secret as part of the list of arguments.
2. Saving the secret to a file and passing the path to generated secrets to the list of arguments.

This choice is reflected in the value `asFile`.

An example of an on-disk RSA key generator is given below:

```python
class RSAPrivKeyGenerator(SecretGenerator):
    """
    Generates RSA privat keys with PEM encoding, PKCS8 and no encryption. The key are written to disk (`/tmp/microsurf_key_gen_**.key`).
    
        Args:
            keylen: The length of the private key in bits.
    """
    def __init__(self, keylen:int):
        # we pass asFile=True because our secrets are loaded from disk (RSA priv key)
        super().__init__(keylen, asFile=True)

    def __call__(self, *args, **kwargs):
        self.pkey = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.keylen
        )
        kbytes = self.pkey.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        tempfile.tempdir = '/tmp'
        keyfile = tempfile.NamedTemporaryFile(prefix="microsurf_key_gen", suffix=".key").name
        with open(keyfile, 'wb') as f:
            f.write(kbytes)
        return keyfile

    def getSecret(self) -> int:
        return self.pkey.private_numbers().p
```

```{hint}
The numerical result of the getSecret method will be used to estimated key bit dependencies. This can be used to analyze selective leakages on parts of the secret (say a single coefficient in RSA) or to force a custom leakage model by returning a masked version of the secret.
```

```{hint}
The existing generators provided in the framework are a bit more complex, since they ensure that the same secrets are used for secret-dependent memory detection and control flow operations.
```

### Using the secret generator

The secret generator has to be passed to the `BinaryLoader` as an argument:

```python
binLoader = BinaryLoader(
        path=binpath,
        args=opensslArgs,
        rootfs=jailroot,
        rndGen=RSAPrivKeyGenerator(2048, nbTraces=10),
        sharedObjects=sharedObjects,
    )
```

Note that a keysize and a number of traces to collect has to be passed. The resulting object is a then called during emulation to create different secrets.
