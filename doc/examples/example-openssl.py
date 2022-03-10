"""
@file example-openssl.py

This is an example on how to use the microsurf library
to test the openssl aes-128-ecb 128 implementation for secret dependent memory accesses

openssl aes-128-cbc -e -in input.bin -out output.bin -nosalt -K hexdata -iv 0
"""

import os
from pathlib import Path
from microsurf.microsurf import SCDetector

# length of the key in bits
KEYLEN = 128


def genRandom() -> str:
    """Generate random key material

    Returns:
        str: string of the hex rep. of the key
    """
    # rbytes = os.urandom(KEYLEN)
    # return f"{int.from_bytes(rbytes, byteorder='big'):x}"
    kbytes = KEYLEN // 4
    fmt = "%0" + str(kbytes) + "x"
    return str.format(fmt % int(os.urandom(kbytes).hex(), 16))


def genFixed() -> str:
    """Generate fixed key material

    Returns:
        str: string of the hex rep. of the key
    """
    fbytes = bytes("A" * KEYLEN, "utf-8")
    return f"{int.from_bytes(fbytes, byteorder='big'):x}"


if __name__ == "__main__":
    # define lib / bin paths
    jailroot = "/home/nicolas/Documents/msc-thesis-work/doc/examples/rootfs/jail-openssl-x8632/"
    binpath = jailroot + "openssl"
    # openssl args, the secret part is marked with '@'
    opensslArgs = [
        "aes-256-cbc",
        "-e",
        "-in",
        "input.bin",
        "-out",
        "output.bin",
        "-nosalt",
        "-K",
        "@",
        "-iv",
        "0",
    ]
    scd = SCDetector(
        binPath=binpath,
        args=opensslArgs,
        randGen=genRandom,
        fixGen=genFixed,
        deterministic=False,
        asFile=False,
        jail=jailroot,
        env={},
    )
    scd.exec()
