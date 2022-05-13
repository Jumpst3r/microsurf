"""
Tests if control flow  based side channel detection works on the binary samples

binaries/secret-dep-cf-1/*.bin

For more information about the given binaries, refer to

binaries/secret-dep-cf-1/readme.md

@author nicolas
"""
import json
import tempfile
from pathlib import Path, PurePath

import pytest

from microsurf import SCDetector
from microsurf.pipeline.DetectionModules import CFLeakDetector
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.utils.generators import openssl_hex_key_generator

PREFIX = "secret-dep-cf-1"
ARCH_SUFIX = ["-arm.bin", "-x86-32.bin", "-x86-64.bin", "-mipsel32.bin", "-riscv64.bin"]
resFile = PurePath(Path(__file__).parent, Path(f"binaries/{PREFIX}/secret-dep.json"))
targets = [
    PurePath(Path(__file__).parent, Path(f"binaries/{PREFIX}/{PREFIX}{arch}"))
    for arch in ARCH_SUFIX
]

rootfs = [PurePath(Path(__file__).parent, Path(f"root-arm64"))]


@pytest.mark.parametrize("binPath", targets)
@pytest.mark.parametrize("rootfsPath", rootfs)
def test_analyze_secret_simple(binPath, rootfsPath, monkeypatch):
    fp = tempfile.TemporaryFile()
    monkeypatch.setattr("sys.stdin", fp)
    with open(resFile) as f:
        data = json.load(f)
        tAddr = data[binPath.name]
    args = ['@']  # single secret arg

    binLoader = BinaryLoader(path=binPath, args=args, rootfs='/tmp',
                             rndGen=openssl_hex_key_generator(16),
                             deterministic=True)

    scd = SCDetector(modules=[
        # DataLeakDetector(binaryLoader=binLoader),
        CFLeakDetector(binaryLoader=binLoader)
    ], addrList=[int(a, 16) for a in tAddr], itercount=20)

    scd.exec()
    df = scd.DF
    tAddr = [int(a, 16) for a in tAddr]
    leaking_symbols = {"main"}
    observed = set(df["Symbol Name"].to_list())

    assert leaking_symbols == observed

    for a in tAddr:
        assert hex(a) in df["Runtime Addr"].to_list()
