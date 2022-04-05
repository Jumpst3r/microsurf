"""
@file openssl-camellia-128.py

This is an example on how to use the microsurf library
to test a toy aes implementation (https://github.com/aguinet/aestoy)

Testing the keyschedule:
aes_keyexpand @ (with 128 bit secret)

"""

import os
import random
import sys
from microsurf.microsurf import SCDetector
from microsurf.pipeline.LeakageModels import hamming, identity
from microsurf.utils.generators import getRandomHexKeyFunction

if __name__ == "__main__":
    # define lib / bin paths

    jailroot = "/home/nicolas/Documents/msc-thesis-work/doc/examples/rootfs/jail-toy-aes32/"

    binpath = jailroot + "aes_process"
    # openssl args, the secret part is marked with '@'
    args = [
        "0",
        "@",
        "AABBCCDDEEFF0001AABBCCDDEEFF0001"
    ]
    sharedObjects = []
    scd = SCDetector(
        binPath=binpath,
        args=args,
        randGen=getRandomHexKeyFunction(128),
        deterministic=False,
        asFile=False,
        jail=jailroot,
        sharedObjects=sharedObjects
    )
   
    scd.exec(report=True)
