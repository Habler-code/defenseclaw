# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Secure Client golden: production Secure Client behavior must not change.

See testdata/secure_client_golden/README.md for what is pinned and how to
regenerate the fixtures after a reviewed, intended change.
"""

from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
GOLDEN_DIR = ROOT / "testdata" / "secure_client_golden"
TRIPWIRE_SCRIPT = ROOT / "scripts" / "secure_client_golden.py"
WINDOWS_GOLDEN_SCRIPT = ROOT / "packaging" / "windows" / "tests" / "secure-client-golden.ps1"
WINDOWS_LIFECYCLE_GOLDEN = GOLDEN_DIR / "windows" / "lifecycle.json"

EXPECTED_FIXTURES = (
    "README.md",
    "source_tripwire.json",
    "go/config_posture.json",
    "go/config_mode_pin.json",
    "go/gateway_posture.json",
    "go/cli_posture.json",
    "go/ipc_socket.json",
    "go/sensor_socket.json",
    "go/setup_command_line.json",
    "windows/lifecycle.json",
    "windows/lifecycle_profile_resolution.json",
    "windows/setup_lifecycle_arguments.json",
    "windows/codex_requirements_empty.toml",
    "windows/codex_requirements_admin.toml",
    "windows/codex_requirements_contract.json",
    "windows/claude_managed_policy_2.1.154.json",
    "windows/claude_managed_policy_2.1.207.json",
    "macos/render_config_action_cursor.yaml",
    "macos/render_config_observe_multi_home_dirs.yaml",
    "macos/render_targets_multi.yaml",
    "macos/aid_endpoints.txt",
    "macos/supported_connectors.txt",
)

PLATFORM_KEYED = (
    "go/config_posture.json",
    "go/config_mode_pin.json",
    "go/ipc_socket.json",
    "go/sensor_socket.json",
)


def _load_tripwire_module():
    spec = importlib.util.spec_from_file_location("secure_client_golden", TRIPWIRE_SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_secure_client_golden_fixtures_exist_and_parse() -> None:
    for name in EXPECTED_FIXTURES:
        path = GOLDEN_DIR / name
        assert path.is_file(), f"missing Secure Client golden fixture: {path}"
        if path.suffix == ".json":
            json.loads(path.read_text(encoding="utf-8"))
    for name in PLATFORM_KEYED:
        entries = json.loads((GOLDEN_DIR / name).read_text(encoding="utf-8"))
        assert set(entries) == {"darwin", "windows"}, (
            f"{name} must carry exactly the Secure Client platforms darwin and windows"
        )


def test_secure_client_source_tripwire_is_current() -> None:
    module = _load_tripwire_module()
    expected = json.loads((GOLDEN_DIR / "source_tripwire.json").read_text(encoding="utf-8"))
    problems = module.drift(expected, module.compute_tripwire(ROOT))
    assert not problems, (
        "Secure Client source tripwire drift (production Secure Client behavior must "
        "not change; if intended, review it and run "
        "`python3 scripts/secure_client_golden.py --update`):\n  - " + "\n  - ".join(problems)
    )


def test_secure_client_tripwire_extracts_whole_functions() -> None:
    module = _load_tripwire_module()
    source = (ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1").read_text(encoding="utf-8-sig")
    text = module.powershell_function_text(source, "Get-DefenseClawFailureActionsBytes")
    assert text.startswith("function Get-DefenseClawFailureActionsBytes {\n")
    assert text.endswith("\n}\n")
    assert "60000" in text
    with pytest.raises(ValueError):
        module.powershell_function_text(source, "Get-DefenseClawThisFunctionDoesNotExist")


def test_secure_client_tripwire_extracts_the_installer_param_block() -> None:
    module = _load_tripwire_module()
    source = (ROOT / "packaging" / "windows" / "install-enterprise.ps1").read_text(encoding="utf-8-sig")
    text = module.powershell_script_param_text(source)
    assert text.startswith("param(\n")
    assert text.endswith("\n)\n")
    assert "[string]$EnterpriseProfile = 'SecureClient'" in text
    with pytest.raises(ValueError):
        module.powershell_script_param_text("function X {\n}\n")


def test_secure_client_tripwire_reports_an_unextractable_definition_as_drift(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A reformatted installer param() block (or a renamed pinned function)
    # must fail with the drift message, not a traceback, and must not update.
    module = _load_tripwire_module()
    monkeypatch.setattr(
        module, "PINNED_POWERSHELL_SCRIPT_PARAMS", ("packaging/windows/DefenseClawEnterprise.psm1",)
    )
    assert module.main([]) == 1
    err = capsys.readouterr().err
    assert "Secure Client source tripwire drift:" in err
    assert "expected exactly one top-level param( block" in err
    assert "Traceback" not in err
    assert module.main(["--update"]) == 1
    assert "cannot update" in capsys.readouterr().err


def test_secure_client_tripwire_pins_the_secure_client_profile_helpers() -> None:
    expected = json.loads((GOLDEN_DIR / "source_tripwire.json").read_text(encoding="utf-8"))
    module_key = "packaging/windows/DefenseClawEnterprise.psm1#"
    installer_key = "packaging/windows/install-enterprise.ps1#"
    for name in (
        "Get-DefenseClawProfileRoots",
        "Test-DefenseClawStandaloneProfile",
        "Test-DefenseClawBrokerEnabled",
        "Test-DefenseClawLayoutBrokerEnabled",
        "Get-DefenseClawGatewayServiceDependencies",
        "Get-DefenseClawClaudeMinimumClientVersion",
        "Get-DefenseClawAgentApplicationControlAttestationSchemaVersion",
        "Assert-DefenseClawNoOtherProfileDeployment",
        "Test-DefenseClawProfileDeploymentInstalled",
        "Test-DefenseClawProfileDeploymentRecordTrusted",
        "$script:DefenseClawEnterpriseProfile",
    ):
        assert module_key + name in expected["powershell"], name
    for name in (
        "Get-DefenseClawBootstrapProfileRoots",
        "Test-DefenseClawBootstrapInteractiveUserSID",
        "Initialize-DefenseClawBootstrapNativePath",
        "param",
    ):
        assert installer_key + name in expected["powershell"], name
    for path in (
        "internal/ipc/server_windows.go",
        "internal/ipc/acl_windows.go",
        "internal/ipc/listen_windows.go",
        "internal/cli/hook_foreign_guard_host.go",
        "internal/cli/hook_foreign_guard_host_windows.go",
    ):
        assert path in expected["files"], path


def test_secure_client_tripwire_pins_only_tracked_files(tmp_path: Path) -> None:
    if shutil.which("git") is None:
        pytest.skip("git is not installed")
    module = _load_tripwire_module()
    repo = tmp_path / "repo"
    (repo / "lib").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    (repo / "lib" / "tracked.sh").write_text("echo tracked\n", encoding="utf-8")
    (repo / "lib" / ".DS_Store").write_bytes(b"\0\1")
    (repo / "lib" / "scratch.sh").write_text("echo local\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repo), "add", "lib/tracked.sh"], check=True)
    tracked = module.tracked_files(repo)
    assert tracked == {"lib/tracked.sh"}
    assert [path.name for path in module.pinned_file_matches(repo, "lib/*", tracked)] == ["tracked.sh"]
    # An exported tree without git still skips dot-files.
    assert module.tracked_files(repo / "lib") is None
    assert [path.name for path in module.pinned_file_matches(repo, "lib/*", None)] == ["scratch.sh", "tracked.sh"]


def test_secure_client_tripwire_ignores_a_finder_file_in_a_pinned_directory() -> None:
    module = _load_tripwire_module()
    stray = ROOT / "packaging" / "scripts" / "lib" / ".DS_Store"
    if stray.exists():
        pytest.skip("this checkout already has packaging/scripts/lib/.DS_Store")
    stray.write_bytes(b"\0")
    try:
        problems = module.drift(
            json.loads((GOLDEN_DIR / "source_tripwire.json").read_text(encoding="utf-8")),
            module.compute_tripwire(ROOT),
        )
    finally:
        stray.unlink()
    assert not any(".DS_Store" in problem for problem in problems), problems


def _windows_powershell_engines() -> list[str]:
    if os.name != "nt":
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


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
@pytest.mark.parametrize(
    "engine",
    _windows_powershell_engines() or (None,),
    ids=lambda engine: Path(engine).stem if engine else "missing",
)
def test_windows_secure_client_lifecycle_golden(engine: str | None) -> None:
    assert engine, "Windows CI must provide Windows PowerShell 5.1"
    completed = subprocess.run(
        [
            engine,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(WINDOWS_GOLDEN_SCRIPT),
            "-GoldenPath",
            str(WINDOWS_LIFECYCLE_GOLDEN),
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
        f"Secure Client Windows lifecycle golden failed under {engine}\n"
        f"stdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
    )
    assert "secure-client-golden: OK" in completed.stdout
