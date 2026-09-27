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
def test_update_notice_stays_off_while_the_descriptor_exists(descriptor: Path) -> None:
    # `defenseclaw upgrade` refuses on every managed host, so the notice that
    # tells the user to run it stays off whatever disable_self_update says.
    assert update_notice._self_update_disabled_by_policy() is False
    for body in (json.dumps({"disable_self_update": True}), json.dumps({"disable_self_update": False}), "not json"):
        descriptor.write_text(body, encoding="utf-8")
        assert update_notice._self_update_disabled_by_policy() is True, body


def test_update_notice_is_silent_on_any_managed_deployment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(update_notice.NO_CHECK_ENV, raising=False)
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.setenv("DEFENSECLAW_CONFIG", str(tmp_path / "missing-config.yaml"))
    monkeypatch.setattr(update_notice, "_windows_self_update_policy", lambda: False)
    monkeypatch.setattr(update_notice, "_latest_cached", lambda: "999.0.0")
    monkeypatch.setattr(upgrade_shim, "managed_deployment", lambda: None)
    assert update_notice.available_message() is not None
    monkeypatch.setattr(upgrade_shim, "managed_deployment", lambda: "standalone")
    assert update_notice.available_message() is None


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


@pytest.mark.skipif(os.name == "nt", reason="install.sh is POSIX")
def test_install_sh_environment_cannot_replace_the_platform_descriptor(tmp_path: Path) -> None:
    # The test hook may only add a descriptor. Pointing it elsewhere must not
    # skip the platform descriptor, or any user could bypass the refusal.
    text = (ROOT / "scripts" / "install.sh").read_text(encoding="utf-8")
    block = text[text.index("# ── Managed hosts") : text.index("# ── Which version")]
    platform = tmp_path / "managed-runtime.json"
    platform.write_text("{}", encoding="utf-8")
    assert "/etc/defenseclaw/managed-runtime.json" in block
    script = 'die() { echo "DIE: $*"; exit 1; }\nOS=linux\n' + block.replace(
        "/etc/defenseclaw/managed-runtime.json", str(platform)
    ) + "\necho proceeded\n"
    for override in (str(tmp_path / "missing.json"), ""):
        completed = subprocess.run(
            ["bash", "-c", script],
            env={"PATH": "/usr/bin:/bin", "DEFENSECLAW_INSTALL_MANAGED_DESCRIPTOR": override},
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert completed.returncode == 1, (override, completed.stdout, completed.stderr)
        assert "managed by your organization" in completed.stdout
        assert "proceeded" not in completed.stdout


def test_upgrade_handoff_refuses_on_managed_hosts() -> None:
    text = (ROOT / "scripts" / "defenseclaw-upgrade.sh").read_text(encoding="utf-8")
    assert "/etc/defenseclaw/managed-runtime.json" in text
    assert "/opt/cisco/defenseclaw/etc/managed-runtime.json" in text
    assert text.rstrip("\n").splitlines()[-1] == "# DefenseClaw upgrade resolver complete v1"
