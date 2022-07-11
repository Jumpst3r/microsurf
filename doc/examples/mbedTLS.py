"""
@file mbed-tls-crypto.py

This is an example on how to use the microsurf library
to test mbedtls using the sample drives program crypt_and_hash
provided by mbedtls
"""

import sys

from microsurf.microsurf import SCDetector
from microsurf.pipeline.DetectionModules import CFLeakDetector, DataLeakDetector
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.utils.generators import mbedTLS_hex_key_generator

if __name__ == "__main__":
    # define lib / bin paths

    
    jailroot = "doc/examples/rootfs/mbedtls/jail-mbedtls-arm64/"
    
    binpath = jailroot + "driver.bin"
    # openssl args, the secret part is marked with '@'
    args = f"0 input output aes-cbc SHA1 @".split()
    sharedObjects = ['libmbedcrypto']
    binLoader = BinaryLoader(
        path=binpath,
        args=args,
        rootfs=jailroot,
        rndGen=mbedTLS_hex_key_generator(128),
        sharedObjects=sharedObjects,
        deterministic=True
    )

    scd = SCDetector(modules=[
        CFLeakDetector(binaryLoader=binLoader, flagVariableHitCount=True),
        DataLeakDetector(binaryLoader=binLoader)
    ]
    )
    ret = binLoader.configure()
    if ret:
        exit(1)
    else:
        scd.exec()
