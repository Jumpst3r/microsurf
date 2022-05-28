"""
@file mbed-tls-crypto.py

This is an example on how to use the microsurf library
to test mbedtls using the sample drives program crypt_and_hash
provided by mbedtls
"""

import sys

from microsurf.microsurf import SCDetector
from microsurf.pipeline.DetectionModules import CFLeakDetector, DataLeakDetector
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.utils.generators import mbedTLS_hex_key_generator

if __name__ == "__main__":
    # define lib / bin paths

    if len(sys.argv) > 1 and sys.argv[1] == 'armv4':
        jailroot = "doc/examples/rootfs/mbedtls/jail-mbedtls-armv4/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'arm64':
        jailroot = "doc/examples/rootfs/mbedtls/jail-mbedtls-arm64/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'armv7':
        jailroot = "doc/examples/rootfs/mbedtls/jail-mbedtls-armv7/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'x8664':
        jailroot = "doc/examples/rootfs/mbedtls/jail-mbedtls-x8664/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'mipsel32':
        jailroot = "doc/examples/rootfs/mbedtls/jail-mbedtls-mipsel32/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'riscv64':
        jailroot = "doc/examples/rootfs/mbedtls/jail-mbedtls-riscv64/"
    else:
        print("usage: openssl-camillia-128.py [arm64, armv7, x8664, mipsel32, riscv64]")
        exit(0)

    binpath = jailroot + "crypt_and_hash"
    # openssl args, the secret part is marked with '@'
    args = [
        "0",
        "input.bin",
        "output.bin",
        "AES-128-CBC",
        "SHA512",
        "@",
    ]
    sharedObjects = ['libmbedcrypto']
    binLoader = BinaryLoader(
        path=binpath,
        args=args,
        rootfs=jailroot,
        rndGen=mbedTLS_hex_key_generator(128),
        sharedObjects=sharedObjects,
        deterministic=True
    )

    scd = SCDetector(modules=[
        CFLeakDetector(binaryLoader=binLoader, flagVariableHitCount=True),
        DataLeakDetector(binaryLoader=binLoader)
    ]
    )
    scd.exec()
