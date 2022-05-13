"""
Tests if memory read based side channel detection works on the binary samples

binaries/secret-dep-mem-1/*.bin

For more information about the given binaries, refer to

binaries/secret-dep-mem-1/readme.md

@author nicolas
"""
import json
import tempfile
from pathlib import Path, PurePath

import pytest

from microsurf import SCDetector
from microsurf.pipeline.DetectionModules import DataLeakDetector
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.utils.generators import openssl_hex_key_generator

PREFIX = "secret-dep-mem-1"
ARCH_SUFIX = ["-arm.bin", "-x86-32.bin", "-x86-64.bin", "-mipsel32.bin", "-riscv64.bin"]
resFile = PurePath(Path(__file__).parent, Path(f"binaries/{PREFIX}/secret-dep.json"))
targets = [
    PurePath(Path(__file__).parent, Path(f"binaries/{PREFIX}/{PREFIX}{arch}"))
    for arch in ARCH_SUFIX
]


@pytest.mark.parametrize("binPath", targets)
def test_analyze_secret_simple(binPath, monkeypatch):
    fd = tempfile.TemporaryFile()
    monkeypatch.setattr("sys.stdin", fd)
    with open(resFile) as f:
        data = json.load(f)
        tAddr = data[binPath.name]
    args = ['@']  # single secret arg

    binLoader = BinaryLoader(path=binPath, args=args, rootfs='/tmp',
                             rndGen=openssl_hex_key_generator(8),
                             deterministic=False)
    scd = SCDetector(modules=[DataLeakDetector(binaryLoader=binLoader)], addrList=[int(a, 16) for a in tAddr],
                     itercount=20)
    scd.exec()
    df = scd.DF
    tAddr = [int(a, 16) for a in tAddr]
    leaking_symbols = {"main"}
    observed = set(df["Symbol Name"].to_list())
    fd.close()
    assert leaking_symbols == observed

    for a in tAddr:
        assert hex(a) in df["Runtime Addr"].to_list()
