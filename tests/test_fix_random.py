"""
Tests if we correctly control all sources of ranomness on all architectures
(for deterministic=True execution)
@author nicolas
"""

import pytest
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.utils.generators import getRandomHexKeyFunction
from pathlib import Path, PurePath


armPath = PurePath(Path(__file__).parent, Path("binaries/random/checkrandom-arm.bin"))

x8632Path = PurePath(
    Path(__file__).parent, Path("binaries/random/checkrandom-x86-32.bin")
)

x8664Path = PurePath(
    Path(__file__).parent, Path("binaries/random/checkrandom-x86-64.bin")
)

mips32Path = PurePath(
    Path(__file__).parent, Path("binaries/random/checkrandom-mipsel32.bin")
)

riscv64Path = PurePath(
    Path(__file__).parent, Path("binaries/random/checkrandom-riscv64.bin")
)

targets = [armPath, x8632Path, x8664Path, mips32Path, riscv64Path]


@pytest.mark.parametrize("binPath", targets)
def test_norandom(capfd, binPath):
    BinaryLoader(
        binPath,
        ["@"],
        deterministic=True,
        rndGen=getRandomHexKeyFunction(3),
        rootfs="/tmp",
    )
    out, _ = capfd.readouterr()
    assert "FAIL" not in out
