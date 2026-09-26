# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0

"""`defenseclaw status` reports the managed_enterprise profile."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from defenseclaw.commands import cmd_status


@pytest.fixture()
def config_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "config.yaml"
    monkeypatch.setattr(cmd_status, "config_path", lambda: path)
    monkeypatch.delenv("DEFENSECLAW_ENTERPRISE_PROFILE", raising=False)
    return path


def test_unmanaged_install_has_no_profile(config_file: Path) -> None:
    config_file.write_text("config_version: 8\nenterprise:\n  profile: standalone\n")
    assert cmd_status._enterprise_profile(SimpleNamespace(deployment_mode="")) == ""


def test_configured_profile_is_reported(config_file: Path) -> None:
    config_file.write_text("config_version: 8\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\n")
    cfg = SimpleNamespace(deployment_mode="managed_enterprise")
    assert cmd_status._enterprise_profile(cfg) == "standalone"


def test_service_pin_wins(config_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_file.write_text("config_version: 8\ndeployment_mode: managed_enterprise\n")
    monkeypatch.setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "Standalone")
    cfg = SimpleNamespace(deployment_mode="managed_enterprise")
    assert cmd_status._enterprise_profile(cfg) == "standalone"


def test_default_follows_platform(config_file: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_file.write_text("config_version: 8\ndeployment_mode: managed_enterprise\n")
    cfg = SimpleNamespace(deployment_mode="managed_enterprise")
    monkeypatch.setattr("sys.platform", "linux")
    assert cmd_status._enterprise_profile(cfg) == "standalone"
    monkeypatch.setattr("sys.platform", "win32")
    assert cmd_status._enterprise_profile(cfg) == "secure_client"


def test_malformed_config_never_raises(config_file: Path) -> None:
    config_file.write_text(": : not yaml [\n")
    cfg = SimpleNamespace(deployment_mode="managed_enterprise")
    assert cmd_status._enterprise_profile(cfg) in {"standalone", "secure_client"}
