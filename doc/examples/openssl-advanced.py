"""
@file openssl-advanced.py

This is an example on how to use the microsurf library
to gather PC traces on the openssl camellia-128-ecbb 128 implementation

openssl camellia-128-ecb -e -in input.bin -out output.bin -nosalt -K hexdata
"""

from collections import defaultdict
import itertools
import pickle
import sys

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns
from microsurf.microsurf import SCDetector
from microsurf.pipeline.DetectionModules import CFLeakDetector, DataLeakDetector
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.utils.generators import getRandomHexKeyFunction

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
        print("usage: openssl-camillia-128.py [arm64, x8632, x8664, mipsel32, riscv64]")
        exit(0)

    binpath = jailroot + "openssl"
    binpath = "/home/nicolas/Documents/msc-thesis-work/tests/binaries/hexbitop/secret-x86-64.bin"

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

    ]
    args = ["@"]
    # sharedObjects = ['libssl', 'libcrypto']

    binLoader = BinaryLoader(path=binpath, args=args, rootfs=jailroot, rndGen=getRandomHexKeyFunction(8))

    scd = SCDetector(modules=[
        CFLeakDetector(binaryLoader=binLoader),
        DataLeakDetector(binaryLoader=binLoader),
    ])

    scd.exec()
    
