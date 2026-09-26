# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""Per-user installers and update notices stay out of the way on a computer
whose DefenseClaw is managed by the organization (standalone enterprise)."""

import json
import os
import subprocess
from pathlib import Path

import pytest

from defenseclaw import update_notice, upgrade_shim

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def descriptor(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "managed-runtime.json"
    monkeypatch.setattr(upgrade_shim, "MANAGED_DESCRIPTORS", (str(path),))
    return path


@pytest.mark.skipif(os.name == "nt", reason="POSIX managed hosts only")
def test_upgrade_and_rollback_refuse_on_a_managed_host(descriptor: Path, capsys: pytest.CaptureFixture[str]) -> None:
    descriptor.write_text("{}", encoding="utf-8")
    for command in (["upgrade", "--yes"], ["rollback", "--yes"]):
        assert upgrade_shim.run(command) == 1
        err = capsys.readouterr().err
        assert "managed by your organization" in err
        assert "Nothing was changed" in err


@pytest.mark.skipif(os.name == "nt", reason="POSIX managed hosts only")
def test_help_still_works_on_a_managed_host(descriptor: Path, capsys: pytest.CaptureFixture[str]) -> None:
    descriptor.write_text("{}", encoding="utf-8")
    assert upgrade_shim.run(["upgrade", "--help"]) == 0
    assert "Usage:" in capsys.readouterr().out


@pytest.mark.skipif(os.name == "nt", reason="POSIX managed hosts only")
def test_update_notice_follows_the_descriptor(descriptor: Path) -> None:
    assert update_notice._self_update_disabled_by_policy() is False
    descriptor.write_text(json.dumps({"disable_self_update": True}), encoding="utf-8")
    assert update_notice._self_update_disabled_by_policy() is True
    descriptor.write_text(json.dumps({"disable_self_update": False}), encoding="utf-8")
    assert update_notice._self_update_disabled_by_policy() is False
    descriptor.write_text("not json", encoding="utf-8")
    assert update_notice._self_update_disabled_by_policy() is True


@pytest.mark.skipif(os.name == "nt", reason="install.sh is POSIX")
def test_install_sh_refuses_before_changing_anything(tmp_path: Path) -> None:
    descriptor = tmp_path / "managed-runtime.json"
    descriptor.write_text("{}", encoding="utf-8")
    home = tmp_path / "home"
    home.mkdir()
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(home),
        "DEFENSECLAW_INSTALL_MANAGED_DESCRIPTOR": str(descriptor),
    }
    completed = subprocess.run(
        ["bash", str(ROOT / "scripts" / "install.sh"), "--yes"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 1
    assert "managed by your organization" in completed.stdout + completed.stderr
    assert list(home.iterdir()) == []


def test_upgrade_handoff_refuses_on_managed_hosts() -> None:
    text = (ROOT / "scripts" / "defenseclaw-upgrade.sh").read_text(encoding="utf-8")
    assert "/etc/defenseclaw/managed-runtime.json" in text
    assert "/opt/cisco/defenseclaw/etc/managed-runtime.json" in text
    assert text.rstrip("\n").splitlines()[-1] == "# DefenseClaw upgrade resolver complete v1"
