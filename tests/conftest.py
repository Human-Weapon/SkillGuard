from __future__ import annotations

import sys

import pytest

WINDOWS = sys.platform == "win32"

collect_ignore_glob = ["fixtures/*"]


@pytest.fixture
def target_dir(tmp_path):
    d = tmp_path / "target"
    d.mkdir()
    return d


@pytest.fixture
def output_dir(tmp_path):
    d = tmp_path / "output"
    return d
