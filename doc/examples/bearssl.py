"""
@file bearssl.py

This is an example on how to use the microsurf library to generate & load secrets from disk.

todo
"""

from microsurf.microsurf import SCDetector
from microsurf.pipeline.DetectionModules import CFLeakDetector, DataLeakDetector
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.utils.generators import bearSSL_RSAPrivKeyGenerator

if __name__ == "__main__":
    jailroot = "doc/examples/rootfs/bearssl/jail-bearssl-x8664/"

    binpath = jailroot + "test_rsa"

    opensslArgs = ['@']

    # sharedObjects = ['libcrypto']

    binLoader = BinaryLoader(
        path=binpath,
        args=opensslArgs,
        rootfs=jailroot,
        rndGen=bearSSL_RSAPrivKeyGenerator(1024),
        sharedObjects=[]
    )

    scd = SCDetector(modules=[
        DataLeakDetector(binaryLoader=binLoader),
        CFLeakDetector(binaryLoader=binLoader, flagVariableHitCount=True),
    ], )

    scd.exec()
