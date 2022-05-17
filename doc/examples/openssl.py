"""
@file openssl.py

This is an example on how to use the microsurf library
to gather PC traces on the openssl camellia-128-ecbb 128 implementation

openssl camellia-128-ecb -e -in input.bin -out output.bin -nosalt -K hexdata
"""

import sys

from microsurf.microsurf import SCDetector
from microsurf.pipeline.DetectionModules import DataLeakDetector, CFLeakDetector
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.utils.generators import openssl_hex_key_generator

if __name__ == "__main__":
    # define lib / bin paths
    if len(sys.argv) > 1 and sys.argv[1] == 'arm64':
        jailroot = "doc/examples/rootfs/openssl/jail-openssl-arm32/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'x8664':
        jailroot = "doc/examples/rootfs/openssl/jail-openssl-x8664/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'mipsel32':
        jailroot = "doc/examples/rootfs/openssl/jail-openssl-mipsel32/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'riscv64':
        jailroot = "doc/examples/rootfs/openssl/jail-openssl-riscv64/"
    else:
        print("usage: openssl.py [arm64, x8632, x8664, mipsel32, riscv64]")
        exit(0)

    binpath = jailroot + "openssl"

    # the arguments to pass to the binary.
    # the secret is marked with a '@' placeholder
    opensslArgs = "aes-128-cbc -e -in input.bin -out output.bin -iv 0 -K @".split()

    # list of objects to trace
    sharedObjects = ['libcrypto']

    binLoader = BinaryLoader(
        path=binpath,
        args=opensslArgs,
        # emulation root directory
        rootfs=jailroot,
        # openssl_hex_key_generator generates hex secrets, these will replace the
        # @ symbol in the arg list during emulation.
        rndGen=openssl_hex_key_generator(128),
        sharedObjects=sharedObjects
    )

    scd = SCDetector(modules=[
        # Secret dependent memory read detection
        DataLeakDetector(binaryLoader=binLoader),
        # Secret dependent control flow detection
        CFLeakDetector(binaryLoader=binLoader, flagVariableHitCount=True),
    ])

    scd.exec()
