"""
Tests if we correctly control all sources of ranomness on all architectures
(for --norandom execution)
@author nicolas
"""

import pytest
from pipeline.Stages import BinaryLoader
from pipeline.Executor import PipeLineExecutor
from pathlib import Path, PurePath
import json


def test_norandom_arm(capfd):
    binPath = PurePath(
        Path(__file__).parent.parent.parent, Path("binaries/random/checkrandom-arm.bin")
    )
    BinaryLoader(binPath, ["@"], dryRunOnly=True, deterministic=True)
    out, _ = capfd.readouterr()
    assert "FAIL" not in out


def test_norandom_ia32(capfd):
    binPath = PurePath(
        Path(__file__).parent.parent.parent,
        Path("binaries/random/checkrandom-x86-32.bin"),
    )
    BinaryLoader(binPath, ["@"], dryRunOnly=True, deterministic=True)
    out, _ = capfd.readouterr()
    assert "FAIL" not in out


def test_norandom_x86_64(capfd):
    binPath = PurePath(
        Path(__file__).parent.parent.parent,
        Path("binaries/random/checkrandom-x86-64.bin"),
    )
    BinaryLoader(binPath, ["@"], dryRunOnly=True, deterministic=True)
    out, _ = capfd.readouterr()
    assert "FAIL" not in out
