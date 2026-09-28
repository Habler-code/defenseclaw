# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Run the standalone lifecycle smokes under the engines that run them.

The standalone profile runs the lifecycle module on PowerShell 7; the
cross-profile lock smoke also runs on Windows PowerShell 5.1, the Secure
Client engine. Both smokes work inside a disposable ProgramData stand-in and
touch no service or real machine root.
"""

from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SMOKES = ROOT / "packaging" / "windows" / "tests"


def _engine(name: str) -> str:
    found = shutil.which(name)
    if not found and name == "pwsh.exe" and os.environ.get("ProgramFiles"):
        candidate = Path(os.environ["ProgramFiles"]) / "PowerShell" / "7" / "pwsh.exe"
        found = str(candidate) if candidate.is_file() else None
    return found or f"<{name} not found>"


CASES = [
    ("enterprise-profile-lifecycle-lock-smoke.ps1", "pwsh.exe"),
    ("enterprise-profile-lifecycle-lock-smoke.ps1", "powershell.exe"),
    ("enterprise-standalone-claude-policy-binding-smoke.ps1", "pwsh.exe"),
    ("enterprise-standalone-manifest-adoption-smoke.ps1", "pwsh.exe"),
    ("enterprise-standalone-recovery-activation-deferral-smoke.ps1", "pwsh.exe"),
    ("enterprise-standalone-recovery-activation-deferral-smoke.ps1", "powershell.exe"),
    ("enterprise-standalone-recovery-gateway-smoke.ps1", "pwsh.exe"),
    ("enterprise-standalone-rollback-sensor-helper-smoke.ps1", "pwsh.exe"),
]


@pytest.mark.skipif(os.name != "nt", reason="runs the Windows lifecycle module")
@pytest.mark.parametrize(("smoke", "engine_name"), CASES, ids=[f"{s.removesuffix('.ps1')}-{e.removesuffix('.exe')}" for s, e in CASES])
def test_standalone_lifecycle_smoke(smoke: str, engine_name: str, tmp_path: Path) -> None:
    if not ctypes.windll.shell32.IsUserAnAdmin():
        pytest.skip("the lifecycle smokes need an elevated administrator")
    engine = _engine(engine_name)
    assert Path(engine).is_file(), f"Windows CI must provide {engine_name}"
    command = [engine, "-NoLogo", "-NoProfile", "-NonInteractive"]
    if engine_name == "powershell.exe":
        command += ["-ExecutionPolicy", "Bypass"]
    result = subprocess.run(
        command + ["-File", str(SMOKES / smoke), "-ScratchRoot", str(tmp_path)],
        capture_output=True, text=True, timeout=900, check=False,
    )
    assert result.returncode == 0, (result.stdout[-4000:], result.stderr[-4000:])
    assert f"{smoke.removesuffix('.ps1')}: OK" in result.stdout
