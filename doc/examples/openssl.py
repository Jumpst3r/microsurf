"""
@file openssl.py

This is an example on how to use the microsurf library
to gather PC traces on the openssl camellia-128-ecbb 128 implementation

openssl camellia-128-ecb -e -in input.bin -out output.bin -nosalt -K hexdata
"""

import sys

from microsurf.microsurf import SCDetector
from microsurf.pipeline.DetectionModules import CFLeakDetector
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.utils.generators import RSAPrivKeyGenerator

if __name__ == "__main__":
    # define lib / bin paths
    # comparative evalutation mode, older OpenSSL version - only x86
    if len(sys.argv) > 1 and sys.argv[1] == 'eval':
        jailroot = "doc/examples/rootfs/openssl/jail-openssl-1.1.1dev-x8664/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'armv4':
        jailroot = "doc/examples/rootfs/openssl/jail-openssl-armv4/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'arm64':
        jailroot = "doc/examples/rootfs/openssl/jail-openssl-arm64/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'x8664':
        jailroot = "doc/examples/rootfs/openssl/jail-openssl-x8664/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'mipsel32':
        jailroot = "doc/examples/rootfs/openssl/jail-openssl-mipsel32/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'core2':
        jailroot = "doc/examples/rootfs/openssl/jail-openssl-80386-core2/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'riscv64':
        jailroot = "doc/examples/rootfs/openssl/jail-openssl-riscv64/"
    else:
        print("usage: openssl.py [armv4, arm64, x8632, x8664, mipsel32, riscv64, core2, eval]")
        exit(0)

    binpath = jailroot + "openssl"

    # the arguments to pass to the binary.
    # the secret is marked with a '@' placeholder
    opensslArgs = "dgst -sha256 -sign @ -out output.bin input.bin".split()
    # opensslArgs = "des3 -in input.bin -out output.bin -iv 0 -nosalt -K @".split()
    # opensslArgs = "version -a".split()
    # opensslArgs = "dgst -SM3 @".split()

    # list of objects to trace
    sharedObjects = ['libcrypto']

    binLoader = BinaryLoader(
        path=binpath,
        args=opensslArgs,
        # emulation root directory
        rootfs=jailroot,
        # openssl_hex_key_generator generates hex secrets, these will replace the
        # @ symbol in the arg list during emulation.
        rndGen=RSAPrivKeyGenerator(2048),
        sharedObjects=sharedObjects,
        deterministic=True
    )

    scd = SCDetector(modules=[
        # Secret dependent memory read detection
        # DataLeakDetector(binaryLoader=binLoader),
        # Secret dependent control flow detection
        CFLeakDetector(binaryLoader=binLoader, flagVariableHitCount=True),
    ], )  # addrList=[0x7fffb7fddbc9], itercount=1000)

    scd.exec()
