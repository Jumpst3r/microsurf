"""
@file openssl-camellia-128.py

This is an example on how to use the microsurf library
to test toy static binaries which expect a single integer argument and 
detects any secret dependent memory access made with the provided argument

"""

from microsurf.microsurf import SCDetector
from microsurf.pipeline.DetectionModules import CFLeakDetector
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.utils.generators import openssl_hex_key_generator

if __name__ == "__main__":
    binpath = "/home/nicolas/Documents/msc-thesis-work/tests/binaries/secret-dep-cf-1/secret-dep-cf-1-x86-64.bin"
    # binpath = "/home/nicolas/Documents/msc-thesis-work/tests/binaries/secret0/secret-x86-32.bin"

    args = ['@']  # single secret arg

    binLoader = BinaryLoader(path=binpath, args=args, rootfs='/tmp', rndGen=openssl_hex_key_generator(10),
                             deterministic=True)

    scd = SCDetector(modules=[
        # DataLeakDetector(binaryLoader=binLoader),
        CFLeakDetector(binaryLoader=binLoader)
    ], addrList=[0x4017b6], itercount=300
    )

    scd.exec()
