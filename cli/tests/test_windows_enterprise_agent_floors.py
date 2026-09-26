# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Windows enterprise agent floors track the hook-contract table (#901).

The Windows installer, lifecycle module and gateway gate each carried a
hard-coded Claude floor of 2.1.152 while the first Claude hook contract starts
at 2.1.154. A 2.1.152 or 2.1.153 client passed every gate and then had no
contract to render a managed policy for.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "cli" / "defenseclaw" / "inventory" / "hook_contracts.json"
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"
INSTALLER = ROOT / "packaging" / "windows" / "install-enterprise.ps1"
GO_GATE = ROOT / "internal" / "enterprisehooks" / "install_windows.go"


def _version(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def _lowest_contract_minimum(connector: str) -> str:
    contracts = json.loads(CONTRACTS.read_text(encoding="utf-8"))["connectors"][connector]["contracts"]
    minimums = [c["agent_version"]["min_inclusive"] for c in contracts if c["agent_version"].get("min_inclusive")]
    return min(minimums, key=_version)


def _installer_placeholders() -> dict[str, str]:
    installer = INSTALLER.read_text(encoding="utf-8")
    block = installer[installer.index("$script:DefenseClawWindowsAgentVersionMinimum = @{") :]
    block = block[: block.index("}")]
    return dict(re.findall(r"'([a-z]+)'\s*=\s*'([0-9.]+)'", block))


def _go_platform_floors() -> dict[str, str]:
    gate = GO_GATE.read_text(encoding="utf-8")
    block = gate[gate.index("var windowsEnterprisePlatformAgentMinimums = map[string]string{") :]
    block = block[: block.index("}")]
    return dict(re.findall(r'"([a-z]+)":\s*"([0-9.]+)"', block))


def test_module_claude_floor_is_the_lowest_claude_hook_contract() -> None:
    module = MODULE.read_text(encoding="utf-8")
    floor = _lowest_contract_minimum("claudecode")
    assert f"$script:ClaudeMinimumClientVersion = '{floor}'" in module
    # Every writer and reader goes through the constant; only the legacy
    # read-compatibility list may still name an older floor.
    literals = set(re.findall(r"'(2\.1\.\d+)'", module))
    assert literals == {floor, "2.1.152"}
    assert "$script:LegacyClaudeMinimumClientVersions = @('2.1.152')" in module
    assert module.count("claude_minimum_client_version = $script:ClaudeMinimumClientVersion") == 2
    assert "minimum_claude_version = $script:ClaudeMinimumClientVersion" in module
    # Existing evidence and metadata recorded the legacy floor and must stay
    # readable, or every lifecycle action on an existing deployment throws.
    assert module.count("-not (Test-DefenseClawClaudeMinimumClientVersion `") == 2


def test_installer_placeholders_match_the_gateway_gate() -> None:
    placeholders = _installer_placeholders()
    assert placeholders["claudecode"] == _lowest_contract_minimum("claudecode")
    platform = _go_platform_floors()
    assert placeholders["codex"] == platform["codex"]
    assert placeholders["cursor"] == platform["cursor"]
    # A contract-rendered connector's placeholder must resolve to a contract.
    assert _version(placeholders["codex"]) >= _version(_lowest_contract_minimum("codex"))


def test_go_gate_derives_the_claude_floor_from_the_contract_table() -> None:
    gate = GO_GATE.read_text(encoding="utf-8")
    assert "func windowsEnterpriseManagedAgentMinimum(name string) string {" in gate
    assert "connector.KnownHookContracts(name)" in gate
    assert '"claudecode": true' in gate
    assert '"claudecode":' not in gate[
        gate.index("var windowsEnterprisePlatformAgentMinimums") : gate.index(
            "var windowsEnterpriseContractRenderedConnectors"
        )
    ]
    # 2.1.152 survives only as the targets.yaml load floor for rows earlier
    # releases wrote; the enrollment gate uses the contract-derived floor.
    legacy = gate[gate.index("var windowsEnterpriseLegacyManifestAgentMinimums") :]
    legacy = legacy[: legacy.index("}")]
    assert dict(re.findall(r'"([a-z]+)":\s*"([0-9.]+)"', legacy)) == {"claudecode": "2.1.152"}
    assert gate.count("2.1.152") == 1


def test_manifest_load_tolerates_legacy_rows_that_enrollment_refuses() -> None:
    manifest_gate = (ROOT / "internal" / "enterprisehooks" / "manifest_windows.go").read_text(encoding="utf-8")
    assert "requireWindowsEnterpriseManifestAgentVersion(" in manifest_gate
    assert "requireWindowsEnterpriseManagedAgentVersion(" not in manifest_gate
    gate = GO_GATE.read_text(encoding="utf-8")
    for platform_gate in ("func platformInstall(", "func platformVerify("):
        body = gate[gate.index(platform_gate) :]
        body = body[: body.index("\n}\n")]
        assert "requireWindowsEnterpriseManagedAgentVersion(" in body
