"""
Tests if address based side channel detection works on the binary sample `nosecret.bin`
For more information about the given binary, refer to binaries/nosecret/readme.md
@author nicolas
"""

import pytest
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.pipeline.Executor import PipeLineExecutor
from pathlib import Path, PurePath
import json


def test_analyze_arm():
    binPath = PurePath(
        Path(__file__).parent, Path("binaries/nosecret/nosecret-arm.bin")
    )
    armTargetAddr = []
    armTargetPath = PurePath(binPath.parent, Path("secret-dep.json"))
    with open(armTargetPath) as f:
        data = json.load(f)
        armTargetAddr = data["secret-arm.bin"]
    bl = BinaryLoader(binPath, ["@"], dryRunOnly=False)
    pipeline = PipeLineExecutor(loader=bl)
    pipeline.run()
    res = pipeline.finalize()
    armTargetAddr = [int(a, 16) for a in armTargetAddr]
    assert res == armTargetAddr


def test_analyze_ia32():
    binPath = PurePath(
        Path(__file__).parent,
        Path("binaries/nosecret/nosecret-x86-32.bin"),
    )
    armTargetAddr = []
    armTargetPath = PurePath(binPath.parent, Path("secret-dep.json"))
    with open(armTargetPath) as f:
        data = json.load(f)
        armTargetAddr = data["secret-x86-32.bin"]
    bl = BinaryLoader(binPath, ["@"], dryRunOnly=False)
    pipeline = PipeLineExecutor(loader=bl)
    pipeline.run()
    res = pipeline.finalize()
    armTargetAddr = [int(a, 16) for a in armTargetAddr]
    assert res == armTargetAddr


def test_analyze_x86_64():
    binPath = PurePath(
        Path(__file__).parent,
        Path("binaries/nosecret/nosecret-x86-64.bin"),
    )
    armTargetAddr = []
    armTargetPath = PurePath(binPath.parent, Path("secret-dep.json"))
    with open(armTargetPath) as f:
        data = json.load(f)
        armTargetAddr = data["secret-x86-64.bin"]
    bl = BinaryLoader(binPath, ["@"], dryRunOnly=False)
    pipeline = PipeLineExecutor(loader=bl)
    pipeline.run()
    res = pipeline.finalize()
    armTargetAddr = [int(a, 16) for a in armTargetAddr]
    assert res == armTargetAddr
