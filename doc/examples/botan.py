"""
@file botan.py

This is an example on how to use the microsurf library to generate & load secrets from disk.

To do so we use the RSAPrivKeyGenerator to create private keys which are then passed to openSSL

botan sign <RSA key> <FILE>
"""
import os
import sys

from microsurf.microsurf import SCDetector
from microsurf.pipeline.DetectionModules import CFLeakDetector, DataLeakDetector
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.utils.generators import SecretGenerator, hex_key_generator


# define a secret generator which produces "--key=<HEX KEY>".
class botan_hex_key(SecretGenerator):
    def __init__(self, keylen):
        super().__init__(keylen, asFile=False)

    def __call__(self, *args, **kwargs) -> str:
        self.hexstr = f"{int.from_bytes(os.urandom(self.keylen // 8), byteorder='big'):0{self.keylen // 8 * 2}x}"
        # returns the string to be inserted in the CLI command
        return f'--key={self.hexstr}'

    def getSecret(self) -> int:
        # returns the secret as an integer
        return int(self.hexstr, 16)


if __name__ == "__main__":
    # define lib / bin paths

    # define lib / bin paths
    if len(sys.argv) > 1 and sys.argv[1] == 'armv4':
        jailroot = "doc/examples/rootfs/botan/jail-botan-armv4/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'armv7':
        jailroot = "doc/examples/rootfs/botan/jail-botan-armv7/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'arm64':
        jailroot = "doc/examples/rootfs/botan/jail-botan-arm64/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'x8664':
        jailroot = "doc/examples/rootfs/botan/jail-botan-x8664/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'mipsel32':
        jailroot = "doc/examples/rootfs/botan/jail-botan-mipsel32/"
    elif len(sys.argv) > 1 and sys.argv[1] == 'riscv64':
        jailroot = "doc/examples/rootfs/botan/jail-botan-riscv64/"
    else:
        print("usage: botan.py [armv4, armv64, x8664, mipsel32, riscv64]")
        exit(0)

    binpath = jailroot + "botan"

    # args = "hash --algo=MD5 @".split(' ')
    # args = "sign --der-format --hash=SHA-256 @ input.bin".split(' ')
    args = "cipher --cipher=AES-128/CBC @ input.bin".split(' ')
    # args = "@".split(' ')

    sharedObjects = ['libbotan']

    binLoader = BinaryLoader(
        path=binpath,
        args=args,
        rootfs=jailroot,
        rndGen=botan_hex_key(128),
        sharedObjects=sharedObjects,
        deterministic=True
    )

    scd = SCDetector(modules=[
        DataLeakDetector(binaryLoader=binLoader),
        CFLeakDetector(binaryLoader=binLoader, flagVariableHitCount=True),
    ])

    scd.exec()
