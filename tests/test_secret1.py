"""
Tests if address based side channel detection works on the binary sample `secret1.bin`
For more information about the given binary, refer to binaries/secret1/readme.md
@author nicolas
"""

import tempfile
import pytest
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.pipeline.Executor import PipeLineExecutor
from pathlib import Path, PurePath
import json, sys


def test_analyze_arm(monkeypatch):
    fp = tempfile.TemporaryFile()
    monkeypatch.setattr('sys.stdin', fp)
    binPath = PurePath(Path(__file__).parent, Path("binaries/secret1/secret-arm.bin"))
    armTargetAddr = []
    armTargetPath = PurePath(binPath.parent, Path("secret-dep.json"))
    with open(armTargetPath) as f:
        data = json.load(f)
        armTargetAddr = data["secret-arm.bin"]
    bl = BinaryLoader(binPath, ["@"], dryRunOnly=False)
    pipeline = PipeLineExecutor(loader=bl)
    pipeline.ITER_COUNT = 160
    pipeline.run()
    res = pipeline.finalize()
    armTargetAddr = [int(a, 16) for a in armTargetAddr]
    fp.close()
    for a in armTargetAddr:
        assert a in res


def test_analyze_ia32(monkeypatch):
    fp = tempfile.TemporaryFile()
    monkeypatch.setattr('sys.stdin', fp)
    binPath = PurePath(
        Path(__file__).parent, Path("binaries/secret1/secret-x86-32.bin")
    )
    armTargetAddr = []
    armTargetPath = PurePath(binPath.parent, Path("secret-dep.json"))
    with open(armTargetPath) as f:
        data = json.load(f)
        armTargetAddr = data["secret-x86-32.bin"]
    bl = BinaryLoader(binPath, ["@"], dryRunOnly=False)
    pipeline = PipeLineExecutor(loader=bl)
    pipeline.ITER_COUNT = 160
    pipeline.run()
    res = pipeline.finalize()
    armTargetAddr = [int(a, 16) for a in armTargetAddr]
    fp.close()
    for a in armTargetAddr:
        assert a in res


def test_analyze_x86_64(monkeypatch):
    fp = tempfile.TemporaryFile()
    monkeypatch.setattr('sys.stdin', fp)
    binPath = PurePath(
        Path(__file__).parent, Path("binaries/secret1/secret-x86-64.bin")
    )
    armTargetAddr = []
    armTargetPath = PurePath(binPath.parent, Path("secret-dep.json"))
    with open(armTargetPath) as f:
        data = json.load(f)
        armTargetAddr = data["secret-x86-64.bin"]
    bl = BinaryLoader(binPath, ["@"], dryRunOnly=False)
    pipeline = PipeLineExecutor(loader=bl)
    pipeline.ITER_COUNT = 160
    pipeline.run()
    res = pipeline.finalize()
    armTargetAddr = [int(a, 16) for a in armTargetAddr]
    fp.close()
    for a in armTargetAddr:
        assert a in res
