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
from microsurf.pipeline.LeakageModels import hamming, identity
from microsurf.utils.generators import getRandomHexKeyFunction

if __name__ == "__main__":
    # define lib / bin paths

    if len(sys.argv) > 1 and sys.argv[1] == 'arm64':
        jailroot = "doc/examples/rootfs/jail-mbedtls-arm64/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'x8632':
        jailroot = "doc/examples/rootfs/jail-openssl-x8632/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'x8664':
        jailroot = "doc/examples/rootfs/jail-mbedtls-x8664/"
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
        "ARIA-128-ECB",
        "SHA1",
        "hex:@",
    ]
    sharedObjects = ['libmbedx509', 'libmbedtls', 'libmbedcrypto']
    scd = SCDetector(
        binPath=binpath,
        args=args,
        randGen=getRandomHexKeyFunction(128),
        deterministic=False,
        asFile=False,
        jail=jailroot,
        sharedObjects=sharedObjects,
        randomTraces='results/assets/trace_rand_90d53267-0571-4cc3-831a-752fa5a7879a.pickle',
        comment="ARM 64 1K traces, MI threshold 0.2",
        threshold=0.1
    )
   
    scd.exec(report=True)
