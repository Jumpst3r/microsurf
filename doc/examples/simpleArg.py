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
from microsurf.pipeline.LeakageModels import hamming, identity

def genRand() -> str:
    return str(random.randint(0,300))

if __name__ == "__main__":

    #binpath = "/home/nicolas/Documents/msc-thesis-work/tests/binaries/multipc/nosecret-x86-32.bin"
    binpath = "/home/nicolas/Documents/msc-thesis-work/tests/binaries/secret0/secret-x86-32.bin"

    args = ['@'] # single secret arg

    scd = SCDetector(
        binPath=binpath,
        args=args,
        randGen=genRand,
        deterministic=False,
        asFile=False,
        leakageModel=identity,
    )
   
    scd.exec(report=True)
