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
from microsurf.utils.generators import hex_key_generator

if __name__ == "__main__":
    # define lib / bin paths
    # comparative evalutation mode, older OpenSSL version - only x86
    if len(sys.argv) > 1 and sys.argv[1] == 'eval':
        jailroot = "doc/examples/rootfs/openssl/jail-openssl-1.1.1dev-x8664/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'noopt':
        jailroot = "doc/examples/rootfs/openssl/jail-openssl-x8664-noopt/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'armv4':
        jailroot = "doc/examples/rootfs/openssl/jail-openssl-armv4/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'armv7':
        jailroot = "doc/examples/rootfs/openssl/jail-openssl-armv7/"
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
        print("usage: openssl.py [armv4, armv7, arm64, x8664, mipsel32, riscv64, eval]")
        exit(0)
    binpath = jailroot + "openssl"

    # the arguments to pass to the binary.
    # the secret is marked with a '@' placeholder
    opensslArgs = "dgst -sha256 -sign @ -out output.bin input.bin".split()
    # opensslArgs = "des3 -in input.bin -out output.bin -nosalt -K @ -iv 0".split()
    # opensslArgs = "aria128 -list".split()
    # opensslArgs = "rand -hex 8".split()
    opensslArgs = "camellia-128-ecb -in input.bin -out output.bin -iv 0 -nosalt -K @".split()
    # opensslArgs = "version -a".split()
    # opensslArgs = "dgst -whirlpool @".split()

    # list of objects to trace
    sharedObjects = ['libcrypto']

    binLoader = BinaryLoader(
        path=binpath,
        args=opensslArgs,
        # emulation root directory
        rootfs=jailroot,
        # openssl_hex_key_generator generates hex secrets, these will replace the
        # @ symbol in the arg list during emulation.
        rndGen=hex_key_generator(128),
        sharedObjects=sharedObjects,
        deterministic=True
    )
    scd = SCDetector(modules=[
        # Secret dependent memory read detection
        DataLeakDetector(binaryLoader=binLoader, granularity=4),
        # Secret dependent control flow detection
        # CFLeakDetector(binaryLoader=binLoader, flagVariableHitCount=True),
    ], getAssembly=False)  # addrList=[0x7fffb7fddbc9], itercount=1000)
    scd.exec()
    exit(0)
    from collections import defaultdict
    res = defaultdict(list)
    for i in range(2, 10, 2):
        for _ in range(6):
            binLoader = BinaryLoader(
                path=binpath,
                args=opensslArgs,
                # emulation root directory
                rootfs=jailroot,
                # openssl_hex_key_generator generates hex secrets, these will replace the
                # @ symbol in the arg list during emulation.
                rndGen=hex_key_generator(128),
                sharedObjects=sharedObjects,
                deterministic=True
            )
            scd = SCDetector(modules=[
                # Secret dependent memory read detection
                DataLeakDetector(binaryLoader=binLoader, granularity=1),
                # Secret dependent control flow detection
                CFLeakDetector(binaryLoader=binLoader, flagVariableHitCount=True),
            ], getAssembly=False)  # addrList=[0x7fffb7fddbc9], itercount=1000)
            scd.initTraceCount = i
            scd.exec()
            res[i].append(len(scd.DF))
            print(f"ddwd: {len(scd.DF)}")

    with open('resdict.pickle', 'bw') as f:
        pickle.dump(res, f)
