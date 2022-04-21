"""
@file openssl-camellia-128.py

This is an example on how to use the microsurf library
to test toy static binaries which expect a single integer argument and 
detects any secret dependent memory access made with the provided argument

"""

import os
import random
import sys
from microsurf.microsurf import SCDetector
from microsurf.pipeline.DetectionModules import DataLeakDetector
from microsurf.pipeline.LeakageModels import hamming, identity
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.utils.generators import getRandomHexKeyFunction

if __name__ == "__main__":

    binpath = "/home/nicolas/Documents/msc-thesis-work/tests/binaries/hexbitop/secret-x86-64.bin"
    #binpath = "/home/nicolas/Documents/msc-thesis-work/tests/binaries/secret0/secret-x86-32.bin"

    args = ['@'] # single secret arg

    binLoader = BinaryLoader(path=binpath, args=args, rootfs='/home/nicolas/Documents/msc-thesis-work/tests/binaries/hexbitop/', rndGen=getRandomHexKeyFunction(8))

    scd = SCDetector(modules=[
        DataLeakDetector(binaryLoader=binLoader, miThreshold=0),
    ])

    scd.exec()
