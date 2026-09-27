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
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CONTRACTS = ROOT / "cli" / "defenseclaw" / "inventory" / "hook_contracts.json"
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"
INSTALLER = ROOT / "packaging" / "windows" / "install-enterprise.ps1"
GO_GATE = ROOT / "internal" / "enterprisehooks" / "install_windows.go"
PLACEHOLDER_SMOKE = ROOT / "packaging" / "windows" / "tests" / "enterprise-claude-placeholder-smoke.ps1"


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
    # The merge client floor (#899) is a separate constant pinned to the
    # connector by test_windows_enterprise_claude_hklm_policy.py.
    merge = re.search(r"\$script:ClaudeManagedSourcesMergeMinimumClientVersion = '(2\.1\.\d+)'", module)
    assert merge is not None
    assert literals == {floor, "2.1.152", merge.group(1)}
    assert "$script:LegacyClaudeMinimumClientVersions = @('2.1.152')" in module
    # Deployment metadata records the floor; Status reports it unless an
    # HKLM merge policy raises it (#899).
    assert module.count("claude_minimum_client_version = $script:ClaudeMinimumClientVersion") == 1
    assert "$claudeMinimumClientVersion = $script:ClaudeMinimumClientVersion" in module
    assert "claude_minimum_client_version = $claudeMinimumClientVersion" in module
    # Attestation evidence records the attested floor, or the constant.
    writer = module[module.index("function Write-DefenseClawAgentApplicationControlAttestation") :]
    writer = writer[: writer.index("\nfunction ")]
    record = writer[writer.index("minimum_claude_version = $(") :]
    record = record[: record.index("claude_effective_policy_verified")]
    assert "Test-DefenseClawClaudeMinimumClientVersion" in record
    assert "$script:ClaudeMinimumClientVersion" in record
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


def test_claude_placeholder_follows_the_detected_hook_contract() -> None:
    # #895 review: the machine-wide Claude policy is rendered from each row's
    # hook contract. A no-client row at the lowest contract beside a detected
    # newer client rewrote the policy on enrollment and staled the evidence.
    installer = INSTALLER.read_text(encoding="utf-8")
    table = re.search(r"\$script:DefenseClawClaudeHookContractMinimums = @\(([^)]*)\)", installer)
    assert table is not None
    contracts = json.loads(CONTRACTS.read_text(encoding="utf-8"))["connectors"]["claudecode"]["contracts"]
    minimums = sorted((c["agent_version"]["min_inclusive"] for c in contracts), key=_version)
    assert re.findall(r"'([0-9.]+)'", table.group(1)) == minimums

    # A detected version counts by its leading major.minor.patch, the part the
    # gateway normalizes (64-bit components, suffix ignored) before it picks
    # the contract, so 2.1.250-beta.1 is on the newest contract.
    key = installer[
        installer.index("function ConvertTo-DefenseClawClaudeContractVersionKey") : installer.index(
            "function Get-DefenseClawClaudeBootstrapPlaceholder"
        )
    ]
    assert "ConvertTo-DefenseClawConnectorMetadataVersion -Value $Value" in key
    assert "-cnotmatch '^([0-9]+)\\.([0-9]+)\\.([0-9]+)'" in key
    assert "[long]::TryParse(" in key
    placeholder = installer[installer.index("function Get-DefenseClawClaudeBootstrapPlaceholder") :]
    placeholder = placeholder[: placeholder.index("\n}\n")]
    assert "ConvertTo-DefenseClawClaudeContractVersionKey -Value ([string]$detected)" in placeholder
    go = (ROOT / "internal" / "gateway" / "connector" / "hook_contract.go").read_text(encoding="utf-8")
    assert (
        "versionNumberRE = regexp.MustCompile(`(?i)(?:^|[^0-9])v?([0-9]+)(?:\\.([0-9]+))?(?:\\.([0-9]+))?`)" in go
    )
    normalize = go[go.index("func NormalizeAgentVersion(") :]
    normalize = normalize[: normalize.index("\n}\n")]
    assert "strconv.Atoi(parts[i])" in normalize

    render = installer[installer.index("function Get-DefenseClawRenderedEnterpriseTargets") :]
    render = render[: render.index("\n$bootstrapEnvironment = $null")]
    # Every row is discovered before the first row is rendered, and Claude
    # rows take the contract-aligned placeholder.
    assert render.index("$claudePlaceholder = Get-DefenseClawClaudeBootstrapPlaceholder `") < render.index(
        "[void]$sb.AppendLine(\"  - user: "
    )
    assert "-Default ([string]$script:DefenseClawWindowsAgentVersionMinimum['claudecode'])" in render


def _powershell_engines() -> list[str]:
    candidates: list[str | None] = [shutil.which("powershell.exe"), shutil.which("pwsh.exe")]
    windows_root = os.environ.get("SystemRoot")
    if windows_root:
        candidates.append(str(Path(windows_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"))
    engines: list[str] = []
    seen: set[str] = set()
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            resolved = str(Path(candidate).resolve())
            if os.path.normcase(resolved) not in seen:
                seen.add(os.path.normcase(resolved))
                engines.append(resolved)
    if not engines and os.name == "nt":
        return ["<no-powershell-engine-found>"]
    return engines


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell installer smoke")
@pytest.mark.parametrize("engine", _powershell_engines())
def test_claude_placeholder_smoke(engine: str, tmp_path: Path) -> None:
    assert engine != "<no-powershell-engine-found>", "no PowerShell engine found on Windows"
    completed = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-File", str(PLACEHOLDER_SMOKE), "-ScratchRoot", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "Claude placeholder smoke passed" in completed.stdout
