"""
@file openssl-camellia-128.py

This is an example on how to use the microsurf library
to test toy static binaries which expect a single integer argument and 
detects any secret dependent memory access made with the provided argument

"""

import random

from microsurf.microsurf import SCDetector
from microsurf.pipeline.DetectionModules import CFLeakDetector, DataLeakDetector
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.utils.generators import hex_key_generator, SecretGenerator

class bit_generator(SecretGenerator):
    # we pass asFile=True because our secrets are directly included as command line arguments (hex strings)
    def __init__(self, keylen):
        super().__init__(keylen, asFile=False)

    def __call__(self, *args, **kwargs) -> str:
        a = random.randint(0,10)
        self.str = '0' if a < 5 else '1'
        return self.str

    def getSecret(self) -> int:
        return int(self.str, 10)

if __name__ == "__main__":
    binpath = "/home/nicolas/test"
    rootfs = '/home/nicolas/Music/x86-64-v2--glibc--bleeding-edge-2021.11-5/x86_64-buildroot-linux-gnu/sysroot'
    args = ['@']  # single secret arg

    binLoader = BinaryLoader(path=binpath, args=args, sharedObjects=['out.bin'], rootfs=rootfs, rndGen=bit_generator(1),
                             deterministic=True)
    if binLoader.configure():
        exit(0)
    scd = SCDetector(modules=[
        DataLeakDetector(binaryLoader=binLoader),
        #CFLeakDetector(binaryLoader=binLoader, flagVariableHitCount=True)
    ],
    )

    scd.exec()
