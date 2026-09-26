# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""`defenseclaw upgrade` / `rollback` refuse on a managed Windows host."""

from __future__ import annotations

import sys
import types

import pytest
from click.testing import CliRunner

from defenseclaw.commands import cmd_upgrade


class _FakeKey:
    def __init__(self, values: dict[str, str]) -> None:
        self.values = values

    def __enter__(self) -> "_FakeKey":
        return self

    def __exit__(self, *_: object) -> None:
        return None


def _fake_winreg(values: dict[str, str] | None) -> types.ModuleType:
    module = types.ModuleType("winreg")
    module.HKEY_LOCAL_MACHINE = object()
    module.KEY_READ = 1
    module.KEY_WOW64_64KEY = 2

    def open_key(_hive, path, _reserved, _access):
        assert path == r"SOFTWARE\Cisco\DefenseClaw\Enterprise"
        if values is None:
            raise FileNotFoundError(path)
        return _FakeKey(values)

    def query_value(key, name):
        if name not in key.values:
            raise FileNotFoundError(name)
        return key.values[name], 1

    module.OpenKey = open_key
    module.QueryValueEx = query_value
    return module


@pytest.mark.parametrize(
    ("values", "expected"),
    [(None, None), ({"Profile": "standalone"}, "standalone"), ({}, "managed")],
)
def test_marker_detection(monkeypatch: pytest.MonkeyPatch, values, expected) -> None:
    monkeypatch.setattr(cmd_upgrade, "os", types.SimpleNamespace(name="nt"))
    monkeypatch.setitem(sys.modules, "winreg", _fake_winreg(values))
    assert cmd_upgrade._managed_enterprise_profile() == expected


def test_marker_is_ignored_off_windows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cmd_upgrade, "os", types.SimpleNamespace(name="posix"))
    assert cmd_upgrade._managed_enterprise_profile() is None


@pytest.mark.parametrize("command", [cmd_upgrade.upgrade, cmd_upgrade.rollback])
def test_commands_refuse_before_running_the_shim(monkeypatch: pytest.MonkeyPatch, command) -> None:
    monkeypatch.setattr(cmd_upgrade, "_managed_enterprise_profile", lambda: "standalone")
    shim = types.ModuleType("defenseclaw.upgrade_shim")

    def run(_argv):
        raise AssertionError("the upgrade shim must not run on a managed host")

    shim.run = run
    monkeypatch.setitem(sys.modules, "defenseclaw.upgrade_shim", shim)
    result = CliRunner().invoke(command, ["--yes"])
    assert result.exit_code == 1
    assert "managed DefenseClaw enterprise deployment (standalone)" in result.output
