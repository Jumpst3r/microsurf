"""
@file openssl-camellia-128.py

This is an example on how to use the microsurf library
to test the openssl camellia-128-ecbb 128 implementation for secret dependent memory accesses

openssl camellia-128-ecb -e -in input.bin -out output.bin -nosalt -K hexdata
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
        jailroot = "/home/nicolas/Documents/msc-thesis-work/doc/examples/rootfs/jail-openssl-arm64/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'x8632':
        jailroot = "/home/nicolas/Documents/msc-thesis-work/doc/examples/rootfs/jail-openssl-x8632/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'x8664':
        jailroot = "/home/nicolas/Documents/msc-thesis-work/doc/examples/rootfs/jail-openssl-x8664/"
    else:
        print("usage: openssl-camillia-128.py [arm64, x8632]")
        exit(0)

    binpath = jailroot + "openssl"
    # openssl args, the secret part is marked with '@'
    opensslArgs = [
        "camellia-128-ecb",
        #"cast5-ecb",
        #"bf-ecb",
        #"des3",
        #"des-ecb",
        "-e",
        "-in",
        "input.bin",
        "-out",
        "output.bin",
        "-nosalt",
        "-K",
        "@",
        #"-iv", # no IV for camellia
        # "0",
    ]
    sharedObjects = ['libssl', 'libcrypto']
    scd = SCDetector(
        binPath=binpath,
        args=opensslArgs,
        randGen=getRandomHexKeyFunction(128),
        deterministic=False,
        asFile=False,
        jail=jailroot,
        sharedObjects=sharedObjects
    )
   
    scd.exec(report=True)
