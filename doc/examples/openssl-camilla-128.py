"""
@file example-openssl.py

This is an example on how to use the microsurf library
to test the openssl aes-128-ecb 128 implementation for secret dependent memory accesses

openssl aes-128-cbc -e -in input.bin -out output.bin -nosalt -K hexdata -iv 0
"""

import os
from pathlib import Path
import sys
from microsurf.microsurf import SCDetector
from microsurf.pipeline.LeakageModels import hamming

# length of the key in bits
KEYLEN = 128


def genRandom() -> str:
    """Generate random key material

    Returns:
        str: string of the hex rep. of the key
    """
    kbytes = KEYLEN // 8
    rbytes = os.urandom(kbytes)
    return f"{int.from_bytes(rbytes, byteorder='big'):x}"


def genFixed() -> str:
    """Generate fixed key material

    Returns:
        str: string of the hex rep. of the key
    """
    kbytes = KEYLEN // 8
    fbytes = bytes("A" * kbytes, "utf-8")
    return f"{int.from_bytes(fbytes, byteorder='big'):x}"


if __name__ == "__main__":
    # define lib / bin paths

    if len(sys.argv) > 1 and sys.argv[1] == 'arm64':
        jailroot = "/home/nicolas/Documents/msc-thesis-work/doc/examples/rootfs/jail-openssl-arm64/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'x8632':
        jailroot = "/home/nicolas/Documents/msc-thesis-work/doc/examples/rootfs/jail-openssl-x8632/"
    else:
        print("usage: openssl-camillia-128.py [arm64, x8632]")
        exit(0)

    binpath = jailroot + "openssl"
    # openssl args, the secret part is marked with '@'
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
        # "-iv", no IV for camellia
        # "0",
    ]
    scd = SCDetector(
        binPath=binpath,
        args=opensslArgs,
        randGen=genRandom,
        fixGen=genFixed,
        deterministic=True,
        asFile=False,
        jail=jailroot,
        leakageModel=hamming,
    )
    scd.exec()
