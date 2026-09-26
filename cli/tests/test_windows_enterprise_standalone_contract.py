# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Contracts for the Windows standalone enterprise profile.

The standalone profile shares the lifecycle module and installer with the
production Cisco Secure Client deployment. These checks keep the Secure
Client roots in one place, keep the two profile-root helpers in lockstep,
and pin the standalone-only guards, pins, and per-user refusals.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"
INSTALLER = ROOT / "packaging" / "windows" / "install-enterprise.ps1"
PER_USER_INSTALLER = ROOT / "scripts" / "install.ps1"
WINPATH_LAYOUT = ROOT / "internal" / "winpath" / "enterprise_layout.go"

SECURE_CLIENT = "Cisco Secure Client"

# Code (not comments) may name the Secure Client vendor directory only in
# these functions: the two profile-root helpers, the CMID provider root the
# Secure Client credential broker loads from, and the cross-profile refusal
# message.
ALLOWED_MODULE_FUNCTIONS = {
    "Get-DefenseClawProfileRoots",
    "Assert-DefenseClawExactScopeService",
    "Assert-DefenseClawNoOtherProfileDeployment",
}
ALLOWED_INSTALLER_FUNCTIONS = {"Get-DefenseClawBootstrapProfileRoots"}


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig")


def _code_lines_by_function(text: str) -> list[tuple[str | None, int, str]]:
    """Yield (enclosing top-level function, line number, code) for every line
    that is not a comment. Here-strings are treated as code."""

    rows: list[tuple[str | None, int, str]] = []
    current: str | None = None
    in_block_comment = False
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if in_block_comment:
            if "#>" in stripped:
                in_block_comment = False
            continue
        if stripped.startswith("<#"):
            in_block_comment = "#>" not in stripped
            continue
        match = re.match(r"^function ([A-Za-z0-9-]+) \{", line)
        if match:
            current = match.group(1)
        elif line.startswith("}"):
            rows.append((current, number, line))
            current = None
            continue
        if stripped.startswith("#"):
            continue
        rows.append((current, number, line))
    return rows


def _functions_naming(text: str, literal: str) -> dict[str | None, list[int]]:
    found: dict[str | None, list[int]] = {}
    for function, number, line in _code_lines_by_function(text):
        if literal in line:
            found.setdefault(function, []).append(number)
    return found


def _function_body(text: str, name: str) -> str:
    start = text.index(f"function {name} {{\n")
    end = text.index("\n}\n", start)
    return text[start : end + 3]


def test_secure_client_roots_are_named_in_one_place() -> None:
    module = _functions_naming(_text(MODULE), SECURE_CLIENT)
    assert set(module) <= ALLOWED_MODULE_FUNCTIONS, {
        name: lines for name, lines in module.items() if name not in ALLOWED_MODULE_FUNCTIONS
    }
    installer = _functions_naming(_text(INSTALLER), SECURE_CLIENT)
    assert set(installer) <= ALLOWED_INSTALLER_FUNCTIONS, {
        name: lines for name, lines in installer.items() if name not in ALLOWED_INSTALLER_FUNCTIONS
    }


def test_module_and_bootstrap_profile_roots_agree() -> None:
    module = _function_body(_text(MODULE), "Get-DefenseClawProfileRoots")
    bootstrap = _function_body(_text(INSTALLER), "Get-DefenseClawBootstrapProfileRoots")
    for body in (module, bootstrap):
        assert "'Cisco\\Cisco Secure Client'" in body
        assert "'Cisco'" in body
        for leaf in ('"$vendor\\DefenseClaw")', '"$vendor\\DefenseClaw-Cert")'):
            assert body.count(leaf) == 2, (leaf, body)


def test_winpath_roots_match_the_powershell_roots() -> None:
    layout = _text(WINPATH_LAYOUT)
    assert 'vendor, powerShell = `Cisco\\Cisco Secure Client`, "SecureClient"' in layout
    assert 'vendor, powerShell = `Cisco`, "Standalone"' in layout
    module = _function_body(_text(MODULE), "Get-DefenseClawProfileRoots")
    assert '"$vendor\\DefenseClaw\\ipc"' in module
    assert '"$vendor\\DefenseClaw-Lifecycle"' in module
    assert 'join(programFiles, vendor, "DefenseClaw", "ipc")' in layout
    assert 'join(programData, vendor, "DefenseClaw-Lifecycle")' in layout


def test_standalone_host_guards_run_before_the_bootstrap() -> None:
    text = _text(INSTALLER)
    guard = text.index("if ($EnterpriseProfile -ceq 'Standalone') {")
    assert text.index("Microsoft.PowerShell.Core\\Set-StrictMode -Version Latest") < guard
    first_function = text.index("\nfunction ")
    assert guard < first_function
    block = text[guard:first_function]
    for code in (
        "powershell7_required:",
        "powershell_32bit_host:",
        "unsupported_architecture:",
        "powershell_constrained_language:",
    ):
        assert code in block, code
    assert "$PSVersionTable.PSVersion.Major -lt 7" in block
    assert "[Environment]::Is64BitProcess" in block
    assert "OSArchitecture" in block
    assert "[Management.Automation.PSLanguageMode]::FullLanguage" in block
    # The Secure Client path refuses the standalone-only arguments instead of
    # silently ignoring them.
    assert "apply only to -EnterpriseProfile Standalone" in block


def test_profile_pin_is_written_only_for_standalone_services() -> None:
    text = _text(MODULE)
    pin = "DEFENSECLAW_ENTERPRISE_PROFILE=standalone"
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if pin not in line:
            continue
        window = "\n".join(lines[max(0, index - 12) : index + 1])
        assert (
            "Test-DefenseClawStandaloneProfile" in window
            or "-not [bool]$Layout.BrokerEnabled" in window
            or "Test-DefenseClawLayoutBrokerEnabled" in window
        ), f"profile pin at line {index + 1} is not gated to the standalone profile"


def test_secure_client_layout_keeps_its_historical_shape() -> None:
    layout = _function_body(_text(MODULE), "Get-DefenseClawLayout")
    # Only standalone layouts carry profile keys.
    assert "$layout['Profile'] = 'Standalone'" in layout
    assert "$layout['BrokerEnabled'] = $false" in layout
    assert "Profile = " not in layout.split("$layout = @{", 1)[1].split("\n    }\n", 1)[0]


def test_per_user_installer_refuses_a_managed_host_before_any_change() -> None:
    text = _text(PER_USER_INSTALLER)
    check = text.index('OpenSubKey("SOFTWARE\\Cisco\\DefenseClaw\\Enterprise")')
    assert "A managed DefenseClaw enterprise deployment" in text
    assert check < text.index("return Invoke-ReleaseInstaller") < text.index("# Lock and log.")
    assert check < text.index("if ($Rollback) { return Invoke-Rollback }")


def test_hash_pinned_manifest_contract_is_shared() -> None:
    module = _text(MODULE)
    installer = _text(INSTALLER)
    for text in (module, installer):
        assert "schema_version" in text and "PayloadManifest" in text
    assert "'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$'" in module
    go = _text(ROOT / "internal" / "cli" / "windows_enterprise_profile.go")
    assert "`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`" in go
    setup = _text(ROOT / "cmd" / "defenseclaw-enterprise-setup" / "platform_windows.go")
    assert '"schema_version": 1, "files": files' in setup


def test_standalone_fresh_install_rollback_removes_its_sensor_helper() -> None:
    # Transaction snapshots do not record the sensor helper, which a fresh
    # install registers first. A failed standalone first install must remove
    # that owned service before the service-absence gate, or root cleanup
    # refuses and every later ensure/uninstall is wedged.
    module = _text(MODULE)
    body = module[
        module.index("function Publish-DefenseClawInstallRollbackIntent") : module.index(
            "function Assert-DefenseClawInstallRollbackRootDescriptor"
        )
    ]
    no_authority = body.index("if (-not $createdAny -and $null -eq $existing)")
    gate = body.index("if (Test-DefenseClawStandaloneProfile) {", no_authority)
    owned = body.index("Assert-DefenseClawStandaloneSensorHelperOwned `", gate)
    remove = body.index("Remove-DefenseClawService -Name $sensorHelperName", owned)
    absence = body.index("Get-DefenseClawManagedServiceNames `", remove)
    assert no_authority < gate < owned < remove < absence
    helper = module[
        module.index("function Assert-DefenseClawStandaloneSensorHelperOwned") : module.index(
            "function Restore-DefenseClawTransaction {"
        )
    ]
    assert "--managed-enterprise(?: --home-dirs" in helper
    assert "'LocalSystem'" in helper
    assert "refusing to manage foreign service" in helper


def test_standalone_rollback_quiesces_the_sensor_helper_before_restoring_files() -> None:
    module = _text(MODULE)
    start = module.index("function Restore-DefenseClawTransaction {")
    body = module[start : module.index("\nfunction ", start + 10)]
    gate = body.index("if (Test-DefenseClawStandaloneProfile) {")
    owned = body.index("Assert-DefenseClawStandaloneSensorHelperOwned `", gate)
    stop = body.index("Stop-DefenseClawService -Name $standaloneSensorHelper", owned)
    ready = body.index("Assert-DefenseClawRestoredTransactionReadyForActivation", stop)
    restart = body.index("Start-DefenseClawService -Name $standaloneSensorHelper", ready)
    services_restart = body.index("Start-DefenseClawTransactionServices `", restart)
    boot_policy = body.index("-Name $standaloneSensorHelper `", services_restart)
    assert gate < owned < stop < ready < restart < services_restart < boot_policy


def test_standalone_runtime_cleanup_scope_owns_its_sensor_helper() -> None:
    module = _text(MODULE)
    body = module[
        module.index("function Assert-DefenseClawTargetRuntimeCleanupScopeExclusive") : module.index(
            "function ", module.index("function Assert-DefenseClawTargetRuntimeCleanupScopeExclusive") + 10
        )
    ]
    gate = body.index("if (Test-DefenseClawStandaloneProfile) {")
    helper = body.index("Get-DefenseClawSensorHelperServiceName `", gate)
    services = body.index("$allServices = @(Microsoft.PowerShell.Management\\Get-Service `")
    assert gate < helper < services


def test_runtime_cleanup_scope_reads_no_unset_root_variable() -> None:
    # The per-profile root refactor removed $vendorRoot from this function
    # but left one read; under StrictMode every rollback that reached it
    # failed with "The variable '$vendorRoot' cannot be retrieved".
    module = _text(MODULE)
    start = module.index("function Assert-DefenseClawTargetRuntimeCleanupScopeExclusive")
    body = module[start : module.index("\nfunction ", start + 10)]
    assert "$vendorRoot" not in body
    assert "(Get-DefenseClawProfileRoots).CertificationStateBase" in body


def test_recorded_artifact_hashes_do_not_require_a_standalone_broker() -> None:
    # Standalone deployments record no broker hash. Requiring one made every
    # standalone upgrade (and ensure on config drift) fail before mutation.
    module = _text(MODULE)
    start = module.index("function Assert-DefenseClawRecordedArtifactHashes")
    body = module[start : module.index("\nfunction ", start + 10)]
    gate = body.index("Test-DefenseClawLayoutBrokerEnabled -Layout $Layout")
    loop = body.index("foreach ($required in $requiredArtifacts)", gate)
    assert gate < loop


def test_standalone_guardian_state_identity_reads_the_runtime_directory() -> None:
    # The guardian publishes hook_guardian_state.json under DEFENSECLAW_HOME
    # (the runtime directory). Looking under StateRoot made the rollback
    # recovery lane reject every fresh guardian report as "not fresh".
    module = _text(MODULE)
    start = module.index("function Get-DefenseClawGuardianStateIdentity")
    body = module[start : module.index("\nfunction ", start + 10)]
    gate = body.index("if (Test-DefenseClawStandaloneProfile) {")
    runtime = body.index("$Layout.RuntimeDirectory", gate)
    join = body.index("hook_guardian_state.json", runtime)
    assert gate < runtime < join
