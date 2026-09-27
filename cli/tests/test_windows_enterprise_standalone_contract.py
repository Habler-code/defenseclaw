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
import subprocess
import sys
from pathlib import Path

import pytest

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
    disabled = body.index("Set-DefenseClawServiceStartMode -Name $standaloneSensorHelper -StartMode 4", owned)
    # The standalone gateway depends on the sensor helper, and Stop-Service
    # without -Force refuses to stop a service with a running dependent. The
    # helper therefore stops only after the loop that stops the gateway, or
    # every rollback with a running gateway aborts before restoring anything.
    service_stops = body.index("Stop-DefenseClawService -Name $name", disabled)
    gateway_in_stop_loop = body.rindex("[string]$snapshot.gateway_service,", disabled, service_stops)
    stop = body.index("Stop-DefenseClawService -Name $standaloneSensorHelper", disabled)
    assert body.count("Stop-DefenseClawService -Name $standaloneSensorHelper") == 1
    ready = body.index("Assert-DefenseClawRestoredTransactionReadyForActivation", stop)
    restart = body.index("Start-DefenseClawService -Name $standaloneSensorHelper", ready)
    services_restart = body.index("Start-DefenseClawTransactionServices `", restart)
    boot_policy = body.index("-Name $standaloneSensorHelper `", services_restart)
    assert gate < owned < disabled < gateway_in_stop_loop < service_stops < stop
    assert stop < ready < restart < services_restart < boot_policy


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


def test_standalone_uninstall_accepts_and_removes_only_its_ipc_directory() -> None:
    # Standalone keeps <InstallRoot>\ipc\ (the sensor helper's AF_UNIX socket)
    # under InstallRoot. Uninstall refused "unexpected directory ... \ipc"
    # before this. The walk may accept only that directory and its exact
    # socket leaves in the standalone profile; removal happens after every
    # service is gone and before the install tree is retired.
    module = _text(MODULE)
    leaves_start = module.index("function Get-DefenseClawStandaloneIPCSocketLeaves")
    leaves = module[leaves_start : module.index("\nfunction ", leaves_start + 10)]
    assert "if (-not (Test-DefenseClawStandaloneProfile)) {" in leaves
    assert "'sensor-helper.sock'" in leaves
    leaf_start = module.index("function Test-DefenseClawStandaloneIPCSocketLeaf")
    leaf = module[leaf_start : module.index("\nfunction ", leaf_start + 10)]
    assert "$Item.PSIsContainer" in leaf
    assert "$Item.LinkTarget" in leaf
    walk_start = module.index("function Assert-DefenseClawManagedInstallTree")
    walk = module[walk_start : module.index("\nfunction ", walk_start + 10)]
    assert "Get-DefenseClawStandaloneIPCSocketLeaves -Layout $Layout" in walk
    assert "$Layout.BinDirectory," in walk and "$Layout.LibexecDirectory" in walk
    uninstall_start = module.index("function Invoke-DefenseClawUninstallLifecycle")
    uninstall = module[uninstall_start : module.index("\nfunction ", uninstall_start + 10)]
    helper = uninstall.index("Remove-DefenseClawService -Name $Layout.SensorHelperServiceName")
    removal = uninstall.index("Remove-DefenseClawStandaloneManagedIPCDirectory -Layout $Layout", helper)
    retire = uninstall.index("Set-DefenseClawInstallTreeRetirementAcls -Layout $Layout", removal)
    assert helper < removal < retire
    smoke = _text(MODULE.parent / "tests" / "enterprise-standalone-ipc-uninstall-smoke.ps1")
    assert "Secure Client allow-list" in smoke
    assert "symbolic link named like the socket (removal)" in smoke


def test_standalone_uninstall_accepts_and_removes_only_the_managed_opencode_plugin() -> None:
    # The standalone guardian installs the managed OpenCode plugin from the
    # payload binaries at <InstallRoot>\share\opencode\defenseclaw.js, the
    # path enterprisepolicy.OpenCodeManagedPluginPath names. Without an
    # allow-list entry uninstall refused "unexpected directory ... \share".
    # The walk may accept only that file and its two directories in the
    # standalone profile; removal happens after every service is gone and
    # before the install tree is retired.
    module = _text(MODULE)
    opencode = _text(ROOT / "internal" / "enterprisepolicy" / "opencode.go")
    assert "`\\share\\opencode\\defenseclaw.js`" in opencode
    paths = _function_body(module, "Get-DefenseClawStandaloneOpenCodePluginPaths")
    assert "if (-not (Test-DefenseClawStandaloneProfile)) {" in paths
    assert "[IO.Path]::Combine([string]$Layout.InstallRoot, 'share')" in paths
    assert "[IO.Path]::Combine($share, 'opencode')" in paths
    assert "[IO.Path]::Combine($directory, 'defenseclaw.js')" in paths
    removal = _function_body(module, "Remove-DefenseClawStandaloneOpenCodeManagedPlugin")
    assert removal.index("unexpected managed OpenCode content") < removal.index("[IO.File]::Delete($plugin)")
    assert "ReparsePoint" in removal
    walk = _function_body(module, "Assert-DefenseClawManagedInstallTree")
    assert "Get-DefenseClawStandaloneOpenCodePluginPaths -Layout $Layout" in walk
    assert "$allowedFiles += [string]$openCodePlugin.PluginPath" in walk
    uninstall = _function_body(module, "Invoke-DefenseClawUninstallLifecycle")
    helper = uninstall.index("Remove-DefenseClawService -Name $Layout.SensorHelperServiceName")
    removed = uninstall.index("Remove-DefenseClawStandaloneOpenCodeManagedPlugin -Layout $Layout", helper)
    retire = uninstall.index("Set-DefenseClawInstallTreeRetirementAcls -Layout $Layout", removed)
    assert helper < removed < retire
    smoke = _text(MODULE.parent / "tests" / "enterprise-standalone-opencode-plugin-uninstall-smoke.ps1")
    assert "Secure Client allow-list" in smoke
    assert "symbolic link named like the plugin (removal)" in smoke
    assert "refused removal still deleted content" in smoke


def test_standalone_credential_store_permissions_return_after_a_reinstall() -> None:
    # A non-purge uninstall resets the retained credential store to
    # administrator-only ACLs; install, upgrade and reconcile give the gateway
    # its entries back, with the Go writer's exact descriptors, before the
    # gateway starts.
    module = _text(MODULE)
    writer = _text(ROOT / "internal" / "cli" / "enterprise_secret_windows.go")
    names = _text(ROOT / "internal" / "managed" / "credentials.go")

    access = re.search(r'windowsSecretDirectoryReaderAccess = "(0x[0-9a-f]+)"', writer)
    assert access is not None
    assert (
        'return "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;" + '
        'windowsSecretDirectoryReaderAccess + ";;;" + reader.String() + ")"'
    ) in writer
    assert 'return "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;" + reader.String() + ")"' in writer
    directory = _function_body(module, "Get-DefenseClawStandaloneSecretsDirectorySddl")
    assert f"'O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;{access.group(1)};;;{{0}})'" in directory
    credential = _function_body(module, "Get-DefenseClawStandaloneSecretFileSddl")
    assert "'O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;{0})'" in credential

    pattern = re.search(r"serviceCredentialNamePattern = regexp\.MustCompile\(`\^(.+)\$`\)", names)
    assert pattern is not None
    repair = _function_body(module, "Set-DefenseClawStandaloneSecretsAcls")
    assert f"-cnotmatch '^{pattern.group(1)}\\z'" in repair
    assert "if (-not (Test-DefenseClawStandaloneProfile)) {" in repair
    assert repair.index("ReparsePoint") < repair.index("Set-DefenseClawStandaloneSecretSddl")

    call = "Set-DefenseClawStandaloneSecretsAcls `"
    install = _function_body(module, "Invoke-DefenseClawInstallLikeLifecycle")
    metadata = install.index("Write-DefenseClawJsonAtomic -Value $newMetadata -Path $Layout.MetadataPath")
    repaired = install.index(call, metadata)
    assert repaired < install.index("Assert-DefenseClawEnterpriseDeployment", metadata)
    assert repaired < install.index("Start-DefenseClawService", metadata)
    reconcile = _function_body(module, "Invoke-DefenseClawReconcileLifecycle")
    assert call in reconcile
    uninstall = _function_body(module, "Invoke-DefenseClawUninstallLifecycle")
    assert "Set-DefenseClawPreservedStateAcls `" in uninstall
    assert call not in uninstall

    smoke = _text(MODULE.parent / "tests" / "enterprise-standalone-secrets-acl-smoke.ps1")
    assert "Set-DefenseClawPreservedStateAcls -Layout" in smoke
    assert "link named like a credential" in smoke


# The standalone PowerShell smokes run inside disposable scratch directories
# and never touch a service or a real machine root, so Windows CI runs every
# one of them on each installed engine (Windows PowerShell 5.1 and 7).
STANDALONE_SMOKES = (
    "enterprise-profile-lifecycle-lock-smoke.ps1",
    "enterprise-profile-deployment-record-smoke.ps1",
    "enterprise-standalone-claude-policy-binding-smoke.ps1",
    "enterprise-standalone-ipc-uninstall-smoke.ps1",
    "enterprise-standalone-opencode-plugin-uninstall-smoke.ps1",
    "enterprise-standalone-recorded-trust-smoke.ps1",
    "enterprise-standalone-root-squat-smoke.ps1",
    "enterprise-standalone-secrets-acl-smoke.ps1",
)


def _standalone_smoke_engines() -> list[str]:
    import os

    if sys.platform != "win32":
        return []
    import winreg

    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion",
        0,
        winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
    ) as current_version:
        program_files_raw, _ = winreg.QueryValueEx(current_version, "ProgramFilesDir")
    candidates = (
        system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe",
        Path(str(program_files_raw)) / "PowerShell" / "7" / "pwsh.exe",
    )
    return [str(path) for path in candidates if path.is_file()]


def test_every_standalone_smoke_is_wired() -> None:
    tests = MODULE.parent / "tests"
    present = {
        path.name
        for path in tests.glob("enterprise-*-smoke.ps1")
        if path.name.startswith(("enterprise-standalone-", "enterprise-profile-"))
    }
    assert present == set(STANDALONE_SMOKES)
    for name in STANDALONE_SMOKES:
        assert f"{name.removesuffix('.ps1')}: OK" in _text(tests / name)


@pytest.mark.skipif(sys.platform != "win32", reason="requires native Windows PowerShell")
@pytest.mark.parametrize("smoke", STANDALONE_SMOKES)
@pytest.mark.parametrize(
    "engine",
    _standalone_smoke_engines() or (None,),
    ids=lambda engine: Path(engine).stem if engine else "missing",
)
def test_standalone_smokes_run_on_every_engine(engine: str | None, smoke: str) -> None:
    assert engine, "Windows CI must provide Windows PowerShell 5.1 or PowerShell 7"
    script = MODULE.parent / "tests" / smoke
    if "#Requires -Version 7" in _text(script) and Path(engine).stem.lower() != "pwsh":
        pytest.skip(f"{smoke} requires PowerShell 7")
    # Each smoke creates, and removes, its own uniquely named scratch tree
    # under the engine's temporary directory. Keep that prefix short: the IPC
    # smoke binds AF_UNIX sockets, whose paths are limited to 108 characters.
    completed = subprocess.run(
        [
            engine,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(script),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8-sig",
        errors="replace",
        timeout=600,
        check=False,
    )
    assert completed.returncode == 0, (
        f"{smoke} failed under {engine}\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
    )
    marker = smoke.removesuffix(".ps1")
    if f"{marker}: SKIP" in completed.stdout:
        pytest.skip(completed.stdout.strip())
    assert f"{marker}: OK" in completed.stdout


def test_bootstrap_admits_a_hash_pinned_installed_module_by_its_recorded_digest() -> None:
    # A hash-pinned deployment keeps no payload manifest after install, so
    # the installed CLI must be able to verify, repair, and uninstall it: the
    # standalone bootstrap takes the module pin from the protected metadata
    # for every action except Install, and never for Secure Client.
    installer = _text(INSTALLER)
    start = installer.index("$bootstrapPinnedModuleSHA256 = ''")
    body = installer[start : installer.index("$bootstrapAllowedSigners = @()", start)]
    recorded = body.index("elseif ($EnterpriseProfile -ceq 'Standalone' -and")
    for condition in (
        "$TrustMode -ceq 'Authenticode' -and",
        "[string]::IsNullOrWhiteSpace($PayloadManifest) -and",
        "$Action -cne 'Install' -and",
        "-not $AllowUnsigned) {",
        "Get-DefenseClawBootstrapRecordedModulePin `",
        "[IO.Path]::Combine($StateRoot, 'install', 'deployment.json')",
        "-InstallerPath $PSCommandPath",
    ):
        assert body.index(condition, recorded) > recorded, condition
    admit = installer.index("-PinnedSHA256 $bootstrapPinnedModuleSHA256", start)
    assert admit > start + len(body)
    helper = installer[
        installer.index("function Get-DefenseClawBootstrapRecordedModulePin {") : installer.index(
            "# QA shorthand renderer helpers"
        )
    ]
    assert "-AllowUnsignedModule" in helper
    assert "[string]$trust.Value -cne 'hash_pinned'" in helper
    assert "[string]$recordedProfile.Value -cne 'standalone'" in helper
    assert "$running -cne [string]$installer.Value" in helper
    # The module then re-admits the rest of the installed payload from the
    # same metadata when no manifest was supplied.
    module = _text(MODULE)
    entry = module[module.index("$entryMetadata = Get-DefenseClawDeploymentMetadata -Layout $layout") :]
    assert entry.index("Initialize-DefenseClawRecordedPayloadTrust `") < 600
