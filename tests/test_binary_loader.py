"""
Tests if the Binary loader class properly loads staticly compiled executables
Includes a dry run emulation with no SC detection.
@author nicolas
"""

import pytest
from microsurf.pipeline.Stages import BinaryLoader
from pathlib import Path


def test_load_arm():
    bins = Path(__file__).parent.glob("binaries/secret1/*-arm.bin")
    fcnt = 0
    for b in bins:
        BinaryLoader(b, ["@"], dryRunOnly=True)
        fcnt += 1
    assert fcnt != 0


def test_load_ia32():
    bins = Path(__file__).parent.glob("binaries/secret1/*-x86-32.bin")
    fcnt = 0
    for b in bins:
        BinaryLoader(b, ["@"], dryRunOnly=True)
        fcnt += 1
    assert fcnt != 0


def test_load_x86_64():
    bins = Path(__file__).parent.glob("binaries/secret1/*-x86-64.bin")
    fcnt = 0
    for b in bins:
        BinaryLoader(b, ["@"], dryRunOnly=True)
        fcnt += 1
    assert fcnt != 0


def test_load_non_existing():
    with pytest.raises(FileNotFoundError) as e:
        BinaryLoader("The answer to life and everything.bin", ["@"], dryRunOnly=True)


def test_no_secret_marker():
    with pytest.raises(ValueError) as e:
        BinaryLoader(
            "The answer to life and everything.bin", ["--arg", "1"], dryRunOnly=True
        )
