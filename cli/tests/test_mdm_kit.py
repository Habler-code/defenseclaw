# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Contracts for the MDM deployment kit (packaging/mdm).

Each script ships as a standalone file an MDM uploads on its own, so shared
helpers are copied rather than sourced; these checks keep the copies
identical, keep the Windows Intune-facing scripts runnable in Windows
PowerShell 5.1, keep every result on the lifecycle-result schema, and pin the
optional release signing jobs.
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
MDM = ROOT / "packaging" / "mdm"
SCHEMA = MDM / "contract" / "lifecycle-result.schema.json"
UNIX_SCRIPTS = ("defenseclaw-enterprise.sh", "detect.sh", "uninstall.sh")
WINDOWS_SHARED = (
    MDM / "windows" / "Invoke-DefenseClawEnterprise.ps1",
    MDM / "windows" / "detect.ps1",
    MDM / "windows" / "uninstall.ps1",
    MDM / "intune" / "windows" / "Install-DefenseClawIntune.ps1",
    MDM / "intune" / "windows" / "Remediate-Detect.ps1",
    MDM / "intune" / "windows" / "Remediate-Fix.ps1",
)
# Scripts Intune runs inside its 32-bit Windows PowerShell 5.1 host.
WINDOWS_51 = [path for path in WINDOWS_SHARED if path.name != "Invoke-DefenseClawEnterprise.ps1"]
SHARED_BEGIN = "# region DefenseClaw MDM shared helpers"
SHARED_END = "# endregion DefenseClaw MDM shared helpers"


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _shell_function(text: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\) \{{.*?^\}}$", text, re.MULTILINE | re.DOTALL)
    if not match:
        match = re.search(rf"^{re.escape(name)}\(\) \{{[^\n]*\}}$", text, re.MULTILINE)
    assert match, f"{name} not found"
    return match.group(0)


def _schema_validator():
    jsonschema = pytest.importorskip("jsonschema")
    return jsonschema.Draft202012Validator(json.loads(_text(SCHEMA)))


def test_every_mdm_script_is_ascii() -> None:
    # Windows PowerShell 5.1 reads BOM-less files as the ANSI code page, and
    # MDM consoles show uploaded scripts; ASCII avoids both problems.
    for path in sorted(MDM.rglob("*")):
        if path.suffix in {".sh", ".ps1"}:
            data = path.read_bytes()
            assert all(byte < 0x80 for byte in data), f"{path.relative_to(ROOT)} has non-ASCII bytes"
            assert b"\r\n" not in data, f"{path.relative_to(ROOT)} has CRLF line endings"


@pytest.mark.parametrize("name", UNIX_SCRIPTS)
def test_linux_and_macos_copies_differ_only_in_platform(name: str) -> None:
    linux = _text(MDM / "linux" / name).splitlines()
    macos = _text(MDM / "macos" / name).splitlines()
    assert len(linux) == len(macos)
    differences = [(a, b) for a, b in zip(linux, macos) if a != b]
    assert differences == [(
        "DC_SCRIPT_OS=linux # linux | darwin - the only line that differs between the copies",
        "DC_SCRIPT_OS=darwin # linux | darwin - the only line that differs between the copies",
    )]


@pytest.mark.parametrize("function", ["dc_platform", "dc_stat_uid", "dc_stat_mode", "dc_trusted_path"])
def test_unix_shared_helpers_are_identical(function: str) -> None:
    bodies = {name: _shell_function(_text(MDM / "linux" / name), function) for name in UNIX_SCRIPTS}
    assert len(set(bodies.values())) == 1, f"{function} differs between {sorted(bodies)}"


@pytest.mark.parametrize("function", ["dc_json_escape", "dc_log", "dc_busy_output"])
def test_wrapper_and_uninstall_helpers_are_identical(function: str) -> None:
    wrapper = _shell_function(_text(MDM / "linux" / "defenseclaw-enterprise.sh"), function)
    uninstall = _shell_function(_text(MDM / "linux" / "uninstall.sh"), function)
    assert wrapper == uninstall


@pytest.mark.parametrize("os_dir", ["linux", "macos"])
@pytest.mark.parametrize("name", UNIX_SCRIPTS)
def test_unix_scripts_parse_and_lint(os_dir: str, name: str) -> None:
    path = MDM / os_dir / name
    assert os.access(path, os.X_OK), f"{path} must be executable"
    assert _text(path).startswith("#!/bin/sh\n")
    for shell in ("sh", "dash", "bash"):
        if shutil.which(shell):
            subprocess.run([shell, "-n", str(path)], check=True)
    if shutil.which("shellcheck"):
        subprocess.run(["shellcheck", "-s", "sh", "-S", "warning", str(path)], check=True)


def test_unix_scripts_pin_their_environment() -> None:
    for name in UNIX_SCRIPTS:
        text = _text(MDM / "linux" / name)
        assert "PATH=/usr/sbin:/usr/bin:/sbin:/bin\n" in text
        assert "LC_ALL=C\n" in text
        assert "umask 077\n" in text
        assert "set -eu\n" in text


def test_unix_wrapper_never_passes_credentials_on_the_command_line() -> None:
    text = _text(MDM / "linux" / "defenseclaw-enterprise.sh")
    assert 'enterprise secret set --name "$DC_SECRET_NAME" --from-stdin --json <"$secret"' in text
    assert "--from-file" not in text
    # The inline-config block warns against credentials and there is no
    # inline-secret setting.
    assert "DC_SECRET_VALUE" not in text
    assert "Never put credentials here" in text


def _run(args: list[str], stdin: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, input=stdin, capture_output=True, text=True, env={}, timeout=60)


def _host_os_dir() -> str:
    return "macos" if os.uname().sysname == "Darwin" else "linux"


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_unix_wrapper_failures_are_schema_results() -> None:
    validator = _schema_validator()
    host = _host_os_dir()
    other = "linux" if host == "macos" else "macos"
    wrapper = str(MDM / host / "defenseclaw-enterprise.sh")
    cases = [
        ([wrapper, "--action", "bogus"], 2, "mdm_invalid_arguments"),
        ([wrapper, "--source", "/nonexistent.deb"], 2, "mdm_invalid_arguments"),
        ([wrapper, "--sha256", "xyz"], 2, "mdm_invalid_arguments"),
        ([wrapper, "--config-stdin", "--secret-name", "k", "--secret-stdin"], 2, "mdm_invalid_arguments"),
        ([wrapper, "--secret-name", "Bad_Name", "--secret-stdin"], 2, "mdm_invalid_arguments"),
        ([wrapper, "--action", "status", "--config-stdin"], 2, "mdm_invalid_arguments"),
        ([wrapper, "--source-url", "http://example.com/x.tar.gz", "--sha256", "0" * 64], 2 if os.geteuid() == 0 else 1, None),
        ([str(MDM / other / "defenseclaw-enterprise.sh")], 2, "mdm_wrong_platform"),
    ]
    if os.geteuid() != 0:
        cases.append(([wrapper], 1, "mdm_not_root"))
        cases.append(([str(MDM / host / "uninstall.sh")], 1, "mdm_not_root"))
    for args, code, error in cases:
        result = _run(args)
        assert result.returncode == code, (args, result.stdout, result.stderr)
        documents = [line for line in result.stdout.splitlines() if line.strip()]
        assert len(documents) == 1, (args, result.stdout)
        document = json.loads(documents[0])
        errors = sorted(validator.iter_errors(document), key=str)
        assert not errors, (args, [e.message for e in errors])
        assert document["exit_code"] == code
        assert document["platform"] == ("darwin" if host == "macos" else "linux") or error == "mdm_wrong_platform"
        if error:
            assert [e["code"] for e in document["errors"]] == [error], (args, document)


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_unix_detect_formats_without_an_installation() -> None:
    if os.geteuid() == 0 and Path("/opt/defenseclaw/bin/defenseclaw-gateway").exists():
        pytest.skip("a deployment is installed on this host")
    detect = str(MDM / _host_os_dir() / "detect.sh")
    result = _run([detect])
    assert result.returncode == 1 and result.stdout == ""
    assert _run([detect, "--format", "value"]).stdout == "not-installed\n"
    assert _run([detect, "--format", "jamf"]).stdout == "<result>not-installed</result>\n"
    assert _run([detect, "--format", "yaml"]).returncode == 2


def _shared_region(text: str) -> str:
    start = text.index(SHARED_BEGIN)
    end = text.index(SHARED_END) + len(SHARED_END)
    return text[start:end]


def test_windows_shared_helpers_are_identical() -> None:
    regions = {path.relative_to(ROOT).as_posix(): _shared_region(_text(path)) for path in WINDOWS_SHARED}
    canonical = regions["packaging/mdm/windows/detect.ps1"]
    drifted = [name for name, region in regions.items() if region != canonical]
    assert not drifted, f"copy the shared region from packaging/mdm/windows/detect.ps1 into {drifted}"


def test_windows_shared_helpers_never_trust_environment_paths() -> None:
    region = _shared_region(_text(WINDOWS_SHARED[0]))
    code = "\n".join(line for line in region.splitlines() if not line.lstrip().startswith("#"))
    assert "$env:ProgramFiles" not in code and "$env:SystemRoot" not in code
    assert "[Microsoft.Win32.RegistryView]::Registry64" in region
    assert "$env:PSModulePath = Join-Path $PSHOME 'Modules'" in region
    for variable in ("DOTNET_", "COMPLUS_", "CORECLR_", "COR_PROFILER", "PSMODULEPATH"):
        assert variable in region


# PowerShell 7 / .NET Core only constructs that break Windows PowerShell 5.1.
PS7_ONLY = [
    (re.compile(r"\?\?"), "null-coalescing ??"),
    (re.compile(r"\?\.[A-Za-z]"), "null-conditional ?."),
    (re.compile(r"\)\s*(&&|\|\|)\s*"), "pipeline chain operators"),
    (re.compile(r"ForEach-Object\s+-Parallel"), "ForEach-Object -Parallel"),
    (re.compile(r"\bToHexString\b"), "[Convert]::ToHexString"),
    (re.compile(r"\bIsPathFullyQualified\b"), "Path.IsPathFullyQualified"),
    (re.compile(r"\]::HashData\("), "static HashData"),
    (re.compile(r"FileSystemAclExtensions"), "FileSystemAclExtensions"),
    (re.compile(r"\bProcessPath\b"), "Environment.ProcessPath"),
    (re.compile(r"\$\w+\.ArgumentList\b"), "ProcessStartInfo.ArgumentList"),
    (re.compile(r"^#Requires -Version 7", re.MULTILINE), "#Requires 7"),
]


@pytest.mark.parametrize("path", WINDOWS_51, ids=lambda p: p.name)
def test_intune_facing_windows_scripts_run_in_powershell_51(path: Path) -> None:
    text = _text(path)
    for pattern, label in PS7_ONLY:
        assert not pattern.search(text), f"{path.name} uses {label}, which Windows PowerShell 5.1 lacks"
    assert "Set-StrictMode -Version 2.0" in text


def test_generic_windows_wrapper_requires_powershell_7() -> None:
    text = _text(MDM / "windows" / "Invoke-DefenseClawEnterprise.ps1")
    assert "#Requires -Version 7.4" in text
    for guard in (
        "unsupported_architecture",
        "powershell_constrained_language",
        "loader_environment_present",
        "powershell7_untrusted",
        "mdm_not_elevated",
    ):
        assert guard in text
    # Credentials only through stdin or an administrator-only file.
    assert "'--from-stdin'" in text and "-StandardInputPath $secret" in text
    assert "-RequireAdminOnly" in text


def test_windows_scripts_use_the_standalone_setup_and_marker() -> None:
    marker = r"SOFTWARE\Cisco\DefenseClaw\Enterprise"
    assert marker in _text(MDM / "windows" / "detect.ps1")
    for path in (MDM / "intune" / "windows" / "Install-DefenseClawIntune.ps1",
                 MDM / "intune" / "windows" / "New-DefenseClawIntunePackage.ps1",
                 MDM / "windows" / "Invoke-DefenseClawEnterprise.ps1"):
        assert "DefenseClawSetup-Enterprise-Standalone-x64.exe" in _text(path)
    setup_main = _text(ROOT / "cmd" / "defenseclaw-enterprise-setup" / "main.go")
    registration = _text(ROOT / "internal" / "cli" / "windows_enterprise_registration.go")
    builder = _text(ROOT / "packaging" / "windows" / "standalone" / "build-setup.sh")
    assert '"allowedsigners":' in setup_main and '"json":' in setup_main and '"/ensure": "ensure"' in setup_main
    assert "WindowsEnterpriseMarkerKey = `SOFTWARE\\Cisco\\DefenseClaw\\Enterprise`" in registration
    assert '"ProductVersion": version' in registration
    assert "DefenseClawSetup-Enterprise-Standalone-x64.exe" in builder


def test_lifecycle_schema_is_draft_2020_12() -> None:
    schema = json.loads(_text(SCHEMA))
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["properties"]["schema_version"] == {"const": 2}
    assert schema["additionalProperties"] is False


def test_release_workflow_signs_enterprise_artifacts_only_when_secrets_exist() -> None:
    yaml = pytest.importorskip("yaml")
    workflow = yaml.safe_load(_text(ROOT / ".github" / "workflows" / "release.yaml"))
    jobs = workflow["jobs"]
    assert jobs["sign"]["needs"] == ["build", "macos-app", "enterprise-windows", "enterprise-macos"]
    for name in ("enterprise-windows", "enterprise-macos"):
        job = jobs[name]
        assert job["needs"] == "validate" and job["if"] == "inputs.operation == 'release'"
        assert job["environment"] == "release"
    rendered = _text(ROOT / ".github" / "workflows" / "release.yaml")
    # Secrets reach steps only through env; GitHub cannot read them in if:.
    assert not re.search(r"^\s*if:.*secrets\.", rendered, re.MULTILINE)
    assert "::notice title=Unsigned standalone Setup::" in rendered
    assert "::notice title=Unsigned enterprise Linux packages::" in rendered
    assert "--sign-command \"$GITHUB_WORKSPACE/packaging/mdm/signing/authenticode-sign.sh\"" in rendered
    build_steps = [step.get("name", "") for step in jobs["build"]["steps"]]
    assert "Collect the standalone enterprise packages" in build_steps
    assert "Sign the enterprise Linux packages (optional)" in build_steps


def test_signing_helpers_refuse_without_credentials(tmp_path: Path) -> None:
    sign = MDM / "signing" / "authenticode-sign.sh"
    target = tmp_path / "file.exe"
    target.write_bytes(b"MZ")
    result = subprocess.run(["bash", str(sign), str(target)], capture_output=True, text=True,
                            env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")})
    assert result.returncode != 0 and "AUTHENTICODE_PFX" in result.stderr
    builder = ROOT / "packaging" / "windows" / "standalone" / "build-setup.sh"
    result = subprocess.run(["bash", str(builder), "--version", "1.0.0", "--payload-dir", str(tmp_path),
                             "--sign-command", str(sign)], capture_output=True, text=True)
    assert result.returncode == 1 and "exclusive" in result.stderr
    for path in (sign, MDM / "signing" / "build-macos-release.sh"):
        if shutil.which("shellcheck"):
            subprocess.run(["shellcheck", "-S", "warning", str(path)], check=True)


def test_secure_client_build_kit_is_untouched_by_the_mdm_kit() -> None:
    # The AVC Secure Client kit is byte-pinned by the source tripwire; the
    # standalone signing channels must not edit it.
    tripwire = json.loads(_text(ROOT / "testdata" / "secure_client_golden" / "source_tripwire.json"))
    pinned = json.dumps(tripwire)
    for path in MDM.rglob("*"):
        assert path.relative_to(ROOT).as_posix() not in pinned
