"""
@file mbed-tls-crypto.py

This is an example on how to use the microsurf library
to test mbedtls using the sample drives program crypt_and_hash
provided by mbedtls
"""

import os
import random
import sys
from microsurf.microsurf import SCDetector
from microsurf.pipeline.DetectionModules import DataLeakDetector, CFLeakDetector
from microsurf.pipeline.LeakageModels import hamming, identity
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.utils.generators import getRandomHexKeyFunction

if __name__ == "__main__":
    # define lib / bin paths

    if len(sys.argv) > 1 and sys.argv[1] == 'arm64':
        jailroot = "doc/examples/rootfs/jail-mbedtls-arm64/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'x8632':
        jailroot = "doc/examples/rootfs/jail-mbedtls-x8632/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'x8664':
        jailroot = "doc/examples/rootfs/jail-mbedtls-x8664-no-ni/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'mipsel32':
        jailroot = "doc/examples/rootfs/jail-openssl-mipsel32/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'riscv64':
        jailroot = "doc/examples/rootfs/jail-openssl-riscv64/"
    else:
        print("usage: openssl-camillia-128.py [arm64, x8632, x8664, mipsel32, riscv64]")
        exit(0)

    binpath = jailroot + "crypt_and_hash"
    # openssl args, the secret part is marked with '@'
    args = [
        "0",
        "input.bin",
        "output.bin",
        "AES-128-ECB",
        "SHA512",
        "hex:@",
    ]
    sharedObjects = ['libmbedx509', 'libmbedtls', 'libmbedcrypto']
    binLoader = BinaryLoader(path=binpath, args=args, rootfs=jailroot, rndGen=getRandomHexKeyFunction(128), sharedObjects=sharedObjects, deterministic=True)

    scd = SCDetector(modules=[
        CFLeakDetector(binaryLoader=binLoader),
        #DataLeakDetector(binaryLoader=binLoader)
        ],
    )
    scd.exec()
