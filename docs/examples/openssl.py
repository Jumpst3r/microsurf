"""
@file openssl.py

This is an example on how to use the microsurf library
to analyze the openssl camellia-128-ecb 128 implementation for secret-dependent memory accesses and control flow operations.

openssl camellia-128-ecb -e -in input.bin -out output.bin -nosalt -K hexdata
"""

from microsurf.microsurf import SCDetector
from microsurf.pipeline.DetectionModules import CFLeakDetector, DataLeakDetector
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.utils.generators import hex_key_generator

if __name__ == "__main__":
    # define lib / bin paths
    emulationDir = "docs/examples/rootfs/openssl/jail-openssl-1.1.1dev-x8664/"
    binaryPath = emulationDir + "openssl"

    # the arguments to pass to the binary.
    # the secret is marked with a '@' placeholder
    '''
    aes-128-ecb 128
    bf-ecb 128
    camellia-128-ecb 128
    cast5-ecb 128
    des-ecb 64
    des3 192
    '''
    opensslArgs = "camellia-128-ecb -in input.bin -out output.bin -nosalt -K @".split()

    # list of objects to trace (the command line utility and the libcrypto library.)
    sharedObjects = ['libcrypto', 'openssl']

    binLoader = BinaryLoader(
        path=binaryPath,
        args=opensslArgs,
        rootfs=emulationDir,
        rndGen=hex_key_generator(keylen=128, nbTraces=5),
        sharedObjects=sharedObjects,
    )

    # Dry run and check whether emulation is supported
    if binLoader.configure():
        exit(1)

    scd = SCDetector(modules=[
            # Secret dependent memory R/W detection
            DataLeakDetector(binaryLoader=binLoader),
            # Secret dependent control flow detection
            CFLeakDetector(binaryLoader=binLoader)
            ]
        )

    scd.exec()
