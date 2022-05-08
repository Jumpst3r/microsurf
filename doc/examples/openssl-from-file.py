"""
@file openssl.py

This is an example on how to use the microsurf library to generate & load secrets from disk.

To do so we use the RSAPrivKeyGenerator to create private keys which are then passed to openSSL

openssl rsautl -encrypt -inkey @ -in input.bin -out output.bin
"""

import sys

from microsurf.microsurf import SCDetector
from microsurf.pipeline.DetectionModules import CFLeakDetector, DataLeakDetector
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.utils.generators import RSAPrivKeyGenerator

if __name__ == "__main__":
    # define lib / bin paths
    if len(sys.argv) > 1 and sys.argv[1] == 'arm64':
        jailroot = "doc/examples/rootfs/jail-openssl-arm64/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'x8632':
        jailroot = "doc/examples/rootfs/jail-openssl-x8632/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'x8664':
        jailroot = "doc/examples/rootfs/jail-openssl-x8664/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'mipsel32':
        jailroot = "doc/examples/rootfs/jail-openssl-mipsel32/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'riscv64':
        jailroot = "doc/examples/rootfs/jail-openssl-riscv64/"
    else:
        print("usage: openssl.py [arm64, x8632, x8664, mipsel32, riscv64]")
        exit(0)

    binpath = jailroot + "openssl"

    opensslArgs = [
        "rsautl",
        "-encrypt",
        "-inkey",
        "@",
        "-in",
        "input.bin",
        "-out",
        "output.bin"
    ]

    sharedObjects = ['libcrypto']

    binLoader = BinaryLoader(
        path=binpath,
        args=opensslArgs,
        rootfs=jailroot,
        rndGen=RSAPrivKeyGenerator(2048),
        sharedObjects=sharedObjects
    )

    scd = SCDetector(modules=[
        DataLeakDetector(binaryLoader=binLoader),
        # CFLeakDetector(binaryLoader=binLoader),
    ])

    scd.exec()
