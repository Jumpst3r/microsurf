"""
@file openssl.py

This is an example on how to use the microsurf library
to gather PC traces on the openssl camellia-128-ecbb 128 implementation

openssl camellia-128-ecb -e -in input.bin -out output.bin -nosalt -K hexdata
"""
import sys

from microsurf.microsurf import SCDetector
from microsurf.pipeline.DetectionModules import CFLeakDetector, DataLeakDetector
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.utils.generators import hex_key_generator, ecdsa_privkey_generator, RSAPrivKeyGenerator

if __name__ == "__main__":
    # define lib / bin paths
    
    jailroot = "doc/examples/rootfs/openssl/jail-openssl-1.1.1dev-x8664/"
   
    binpath = jailroot + "openssl"

    # the arguments to pass to the binary.
    # the secret is marked with a '@' placeholder
    # opensslArgs = "pkeyutl -sign -in input-rsa.bin -out output.bin -inkey @ -pkeyopt digest:sha1".split()
    opensslArgs = "aes-128-ecb -in input.bin -out output.bin -nosalt -K @ -iv 0".split()
    # opensslArgs = "dgst -sha1 -sign @ -out output.bin input.bin".split()
    # opensslArgs = "aria128 -list".split()
    # opensslArgs = "rand -hex 8".split()
    # opensslArgs = "cast-128-cbc -in input.bin -iv 0 -out output.bin -nosalt -K @".split()
    # opensslArgs = "version -a".split()
    # opensslArgs = "dgst -whirlpool @".split()

    # list of objects to trace
    sharedObjects = ['libcrypto', 'openssl']

    binLoader = BinaryLoader(
        path=binpath,
        args=opensslArgs,
        rootfs=jailroot,
        rndGen=hex_key_generator(128),
        # rndGen=RSAPrivKeyGenerator(2048),
        sharedObjects=sharedObjects,
    )
    if binLoader.configure(): exit(0)
    scd = SCDetector(modules=[
        # Secret dependent memory read detection
        DataLeakDetector(binaryLoader=binLoader),
        # Secret dependent control flow detection
        CFLeakDetector(binaryLoader=binLoader, flagVariableHitCount=True)
    ], 
    getAssembly=False
    )
    scd.initTraceCount = 45
    scd.exec()
