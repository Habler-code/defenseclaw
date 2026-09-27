# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""The standalone Linux units pass `systemd-analyze verify` as installed."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "test-systemd-units.sh"
UNITS = ROOT / "packaging" / "systemd"

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux") or shutil.which("systemd-analyze") is None,
    reason="needs systemd-analyze on Linux",
)


def _verify(units: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["bash", str(SCRIPT), str(units)], capture_output=True, text=True, timeout=300, check=False)


def test_standalone_systemd_units_verify_clean() -> None:
    result = _verify(UNITS)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "units clean" in result.stdout


def test_systemd_unit_check_fails_on_any_diagnostic(tmp_path: Path) -> None:
    # systemd-analyze exits 0 for an unknown key; the check must still fail.
    for unit in UNITS.iterdir():
        if unit.suffix in {".service", ".socket", ".path", ".timer"}:
            shutil.copy(unit, tmp_path / unit.name)
    gateway = tmp_path / "defenseclaw-gateway.service"
    gateway.write_text(gateway.read_text(encoding="utf-8").replace("[Service]\n", "[Service]\nNotARealDirective=1\n", 1), encoding="utf-8")
    result = _verify(tmp_path)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "NotARealDirective" in result.stderr
