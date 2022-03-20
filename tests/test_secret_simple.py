"""
Tests if address based side channel detection works on the binary sample `secret0.bin`
For more information about the given binary, refer to binaries/secret0/readme.md
@author nicolas
"""

import tempfile
import pytest
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.pipeline.Executor import PipeLineExecutor
from microsurf.utils.generators import genRandInt
from microsurf.pipeline.LeakageModels import identity
from microsurf import SCDetector
from pathlib import Path, PurePath
import json, sys


resFile = PurePath(Path(__file__).parent, Path("binaries/secret0/secret-dep.json"))

armPath = PurePath(Path(__file__).parent, Path("binaries/secret0/secret-arm.bin"))

x8632Path = PurePath(
    Path(__file__).parent, Path("binaries/secret0/secret-x86-32.bin")
)

x8664Path = PurePath(
    Path(__file__).parent, Path("binaries/secret0/secret-x86-32.bin")
)

targets = [armPath, x8632Path, x8664Path]


@pytest.mark.parametrize("binPath", targets)
def test_analyze_secret_simple(monkeypatch, binPath):
    fp = tempfile.TemporaryFile()
    monkeypatch.setattr("sys.stdin", fp)
    armTargetAddr = []
    with open(resFile) as f:
        data = json.load(f)
        armTargetAddr = data[binPath.name]
    scd = SCDetector(
        binPath=binPath,
        args=["@"],
        randGen=genRandInt,
        deterministic=False,
        asFile=False,
    )
    res = scd.exec()
    armTargetAddr = [int(a, 16) for a in armTargetAddr]
    fp.close()
    for a in armTargetAddr:
        assert a in res
