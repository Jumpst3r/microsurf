"""
@file openssl.py

This is an example on how to use the microsurf library
to gather PC traces on the openssl camellia-128-ecbb 128 implementation

openssl camellia-128-ecb -e -in input.bin -out output.bin -nosalt -K hexdata
"""
import pickle
import sys

from microsurf.microsurf import SCDetector
from microsurf.pipeline.DetectionModules import CFLeakDetector, DataLeakDetector
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.utils.generators import hex_key_generator, RSAPrivKeyGenerator

if __name__ == "__main__":
    # define lib / bin paths
    # comparative evalutation mode, older OpenSSL version - only x86
    if len(sys.argv) > 1 and sys.argv[1] == 'armv4':
        jailroot = "doc/examples/rootfs/wolfssl/jail-wolfssl-armv4/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'armv7':
        jailroot = "doc/examples/rootfs/wolfssl/jail-wolfssl-armv7/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'arm64':
        jailroot = "doc/examples/rootfs/wolfssl/jail-wolfssl-arm64/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'x8664':
        jailroot = "doc/examples/rootfs/wolfssl/jail-wolfssl-x8664/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'mipsel32':
        jailroot = "doc/examples/rootfs/wolfssl/jail-wolfssl-mipsel32/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'riscv64':
        jailroot = "doc/examples/rootfs/wolfssl/jail-wolfssl-riscv64/"
    else:
        print("usage: wolfssl.py [armv4, armv64, x8664, mipsel32, riscv64]")
        exit(0)

    binpath = jailroot + "aes-file-encrypt"

    args = "@ input.bin output.bin".split(" ")

    sharedObjects = []

    binLoader = BinaryLoader(
        path=binpath,
        args=args,
        rootfs=jailroot,
        rndGen=hex_key_generator(128),
        sharedObjects=sharedObjects,
        deterministic=True
    )

    scd = SCDetector(modules=[
        CFLeakDetector(binaryLoader=binLoader, flagVariableHitCount=True),
        DataLeakDetector(binaryLoader=binLoader)
    ], getAssembly=True
    )
    scd.exec()
