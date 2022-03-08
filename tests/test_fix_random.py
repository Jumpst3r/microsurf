"""
Tests if we correctly control all sources of ranomness on all architectures
(for --norandom execution)
@author nicolas
"""

import pytest
from microsurf.pipeline.Stages import BinaryLoader
from microsurf.pipeline.Executor import PipeLineExecutor
from pathlib import Path, PurePath
import json, sys, tempfile


def test_norandom_arm(capfd, monkeypatch):
    fp = tempfile.TemporaryFile()
    monkeypatch.setattr('sys.stdin', fp)

    binPath = PurePath(
        Path(__file__).parent, Path("binaries/random/checkrandom-arm.bin")
    )
    BinaryLoader(binPath, ["@"], dryRunOnly=True, deterministic=True)
    out, _ = capfd.readouterr()
    assert "FAIL" not in out


def test_norandom_ia32(capfd, monkeypatch):
    fp = tempfile.TemporaryFile()
    monkeypatch.setattr('sys.stdin', fp)
    binPath = PurePath(
        Path(__file__).parent,
        Path("binaries/random/checkrandom-x86-32.bin"),
    )
    BinaryLoader(binPath, ["@"], dryRunOnly=True, deterministic=True)
    out, _ = capfd.readouterr()
    assert "FAIL" not in out


def test_norandom_x86_64(capfd, monkeypatch):
    fp = tempfile.TemporaryFile()
    monkeypatch.setattr('sys.stdin', fp)
    binPath = PurePath(
        Path(__file__).parent,
        Path("binaries/random/checkrandom-x86-64.bin"),
    )
    BinaryLoader(binPath, ["@"], dryRunOnly=True, deterministic=True)
    out, _ = capfd.readouterr()
    assert "FAIL" not in out
