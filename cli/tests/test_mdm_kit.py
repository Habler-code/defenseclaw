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
@pytest.mark.parametrize("os_dir", ["linux", "macos"])
def test_unix_wrapper_creates_a_traversable_log_directory(os_dir: str, tmp_path: Path) -> None:
    # The wrapper runs under umask 077. On macOS its log parent
    # /Library/Logs/Cisco also holds the gateway's own log, which launchd opens
    # as the service account; a 0700 parent kept the gateway from starting.
    layout = _shell_function(_text(MDM / os_dir / "defenseclaw-enterprise.sh"), "dc_layout")
    log = tmp_path / "Logs" / "Cisco" / "DefenseClaw" / "mdm-wrapper.log"
    script = "umask 077\nDC_SCRIPT_OS=darwin\nDC_LOG='%s'\n%s\ndc_layout\n" % (log, layout)
    result = subprocess.run(["sh", "-c", script], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    for directory in (log.parent.parent, log.parent):
        assert directory.stat().st_mode & 0o777 == 0o755, directory


_PACKAGE_TOOL_STUBS = {
    # Each stub answers the queries dc_install_package makes and records any
    # install in $DC_TEST_LOG.
    "dpkg-deb": """case "$3" in Package) echo defenseclaw-enterprise ;; Version) echo "$DC_TEST_VERSION" ;; Architecture) echo amd64 ;; esac""",
    "dpkg": """case "$1" in --print-architecture) echo amd64 ;; -i) echo "dpkg -i" >>"$DC_TEST_LOG" ;; esac""",
    "dpkg-query": "exit 1",
    "rpm": """case "$1" in
    -qp) case "$3" in *NAME*) echo defenseclaw-enterprise ;; *) echo "$DC_TEST_VERSION" ;; esac ;;
    -q) exit 1 ;;
    -U) echo "rpm -U" >>"$DC_TEST_LOG" ;;
esac""",
    "pkgutil": """case "$1" in
    --expand) mkdir -p "$3" && printf '<pkg-ref id="com.cisco.defenseclaw.enterprise" version="%s" onConclusion="none">x.pkg</pkg-ref>\\n' "$DC_TEST_VERSION" >"$3/Distribution" ;;
    *) exit 1 ;;
esac""",
    "installer": 'echo "installer -pkg" >>"$DC_TEST_LOG"',
}


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
@pytest.mark.parametrize(
    ("source", "package_version", "pin", "installs"),
    [
        ("defenseclaw-enterprise.deb", "1.5.0", "1.4.0", False),
        ("defenseclaw-enterprise.deb", "1.4.0", "v1.4.0", True),
        ("defenseclaw-enterprise.deb", "1:1.4.0~rc1-1", "1.4.0-rc1", True),
        ("defenseclaw-enterprise.deb", "1.4.0~rc1", "1.4.0", False),
        ("defenseclaw-enterprise.rpm", "1.5.0-1", "1.4.0", False),
        ("defenseclaw-enterprise.rpm", "1.4.0~rc1-1", "1.4.0-rc1", True),
        ("defenseclaw-enterprise.pkg", "1.5.0", "1.4.0", False),
        ("defenseclaw-enterprise.pkg", "1.4.0-rc1", "1.4.0", False),
        ("defenseclaw-enterprise.pkg", "1.4.0", "1.4.0", True),
        ("defenseclaw-enterprise.deb", "1.5.0", "", True),
    ],
)
def test_unix_wrapper_checks_the_product_version_before_the_package_manager(
    source: str, package_version: str, pin: str, installs: bool, tmp_path: Path
) -> None:
    # The package's maintainer scripts apply the deployment as soon as the
    # package manager installs it, so a --product-version mismatch must stop
    # the wrapper before dpkg, rpm or installer runs.
    text = _text(MDM / "linux" / "defenseclaw-enterprise.sh")
    functions = "\n".join(
        _shell_function(text, name)
        for name in ("dc_busy_output", "dc_require_product_version", "dc_package_release_version", "dc_install_package")
    )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in _PACKAGE_TOOL_STUBS.items():
        stub = bin_dir / name
        stub.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
        stub.chmod(0o755)
    log = tmp_path / "install.log"
    script = f"""
DC_SCRIPT_OS={"darwin" if source.endswith(".pkg") else "linux"}
DC_EXIT_FAILURE=1 DC_EXIT_INVALID=2 DC_EXIT_BUSY=75
DC_LINUX_PACKAGE=defenseclaw-enterprise DC_MACOS_PACKAGE_ID=com.cisco.defenseclaw.enterprise
DC_PRODUCT_VERSION='{pin}' DC_STAGE='{tmp_path}' DC_STAGED_SOURCE='{tmp_path / source}'
dc_fail_result() {{ echo "FAIL $2: $3"; exit "$1"; }}
dc_log() {{ :; }}
dc_extract_payload() {{ :; }}
{functions}
dc_install_package
echo installed-ok
"""
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "DC_TEST_VERSION": package_version, "DC_TEST_LOG": str(log)}
    for shell in ("sh", "bash"):
        if log.exists():
            log.unlink()
        result = subprocess.run([shell, "-c", script], env=env, capture_output=True, text=True, timeout=30)
        if installs:
            assert result.returncode == 0 and "installed-ok" in result.stdout, (shell, result.stdout, result.stderr)
            assert log.exists(), (shell, "the package manager did not run")
        else:
            assert result.returncode == 1, (shell, result.stdout, result.stderr)
            assert "FAIL mdm_version_mismatch" in result.stdout, (shell, result.stdout)
            assert not log.exists(), (shell, "the package manager ran before the version check", log.read_text())


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


@pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")
def test_unix_detect_reads_top_level_fields_of_the_indented_lifecycle_result() -> None:
    # The lifecycle prints indented JSON; detect.sh must read the top-level
    # "installed" and version fields from it, and a nested "ok" must never
    # answer for the top-level one.
    text = _text(MDM / "linux" / "detect.sh")
    functions = "\n".join(_shell_function(text, name) for name in ("dc_json_top", "dc_json_field", "dc_json_true"))
    indented = json.dumps({
        "schema_version": 2, "ok": False, "installed": True, "installed_version": "1.2.3",
        "services": [{"name": "gateway", "ok": True}], "errors": [{"code": "x", "message": "a \"quoted\" : value"}],
    }, indent=2)
    script = functions + """
doc=$(cat)
dc_json_true "$doc" installed && echo installed
dc_json_true "$doc" ok && echo ok-true
echo "version=$(dc_json_field "$doc" installed_version)"
"""
    for shell in ("sh", "dash", "bash"):
        if not shutil.which(shell):
            continue
        result = subprocess.run([shell, "-c", script], input=indented, capture_output=True, text=True, check=True)
        assert result.stdout.splitlines() == ["installed", "version=1.2.3"], (shell, result.stdout)


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


def _pwsh7() -> str | None:
    candidates = [shutil.which("pwsh.exe")]
    program_files = os.environ.get("ProgramFiles")
    if program_files:
        candidates.append(str(Path(program_files) / "PowerShell" / "7" / "pwsh.exe"))
    return next((c for c in candidates if c and Path(c).is_file()), None)


_ANCESTOR_PROBE = r"""
$ErrorActionPreference = 'Stop'
__FUNCTIONS__
function New-ProbeDirectory([string]$Path, [string]$Sddl) {
    $security = [System.Security.AccessControl.DirectorySecurity]::new()
    $security.SetSecurityDescriptorSddlForm($Sddl)
    [System.IO.FileSystemAclExtensions]::Create([System.IO.DirectoryInfo]::new($Path), $security)
}
function New-ProbeFile([string]$Path) {
    [System.IO.File]::WriteAllText($Path, "deployment_mode: managed_enterprise`n")
    $acl = Get-Acl -LiteralPath $Path
    $acl.SetSecurityDescriptorSddlForm('D:P(A;;FA;;;SY)(A;;FA;;;BA)')
    Set-Acl -LiteralPath $Path -AclObject $acl
}
$adminOnly = 'O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
$root = Join-Path ([Environment]::GetFolderPath('Windows')) ('Temp\dc-mdm-ancestors-' + [Guid]::NewGuid().ToString('N'))
try {
    New-ProbeDirectory $root $adminOnly
    New-ProbeDirectory (Join-Path $root 'good') $adminOnly
    New-ProbeFile (Join-Path $root 'good\config.yaml')
    # Authenticated Users may modify (and so rename) this folder; the file in
    # it is still administrator-only.
    New-ProbeDirectory (Join-Path $root 'open') 'O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1301bf;;;AU)'
    New-ProbeFile (Join-Path $root 'open\config.yaml')
    $null = New-Item -ItemType Junction -Path (Join-Path $root 'link') -Target (Join-Path $root 'good')
    $result = [ordered]@{}
    foreach ($name in 'good', 'open', 'link') {
        $file = Join-Path $root "$name\config.yaml"
        $result[$name] = [ordered]@{
            item = [bool](Test-DefenseClawAdminOnlyItem -Path $file)
            ancestors = [bool](Test-WrapperAdminOnlyAncestors -Path $file)
        }
    }
    $result | ConvertTo-Json -Compress
} finally {
    $link = Join-Path $root 'link'
    if (Test-Path -LiteralPath $link) { [System.IO.Directory]::Delete($link) }
    if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
}
"""


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL behaviour")
def test_generic_windows_wrapper_checks_every_folder_above_config_and_secret(tmp_path: Path) -> None:
    # An account that can rename a folder above an administrator-only config
    # can swap the file between the ACL check and the copy, so the wrapper
    # checks the whole chain like the Unix dc_trusted_path.
    engine = _pwsh7()
    assert engine, "Windows CI must provide PowerShell 7"
    text = _text(MDM / "windows" / "Invoke-DefenseClawEnterprise.ps1")
    start = text.index("function Test-WrapperAdminOnlyAncestors {")
    ancestors = text[start : text.index("\nfunction Copy-WrapperInput", start)]
    probe = tmp_path / "ancestor-probe.ps1"
    probe.write_text(_ANCESTOR_PROBE.replace("__FUNCTIONS__", _shared_region(text) + "\n" + ancestors), encoding="utf-8")
    result = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(probe)],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    verdicts = json.loads(result.stdout.strip().splitlines()[-1])
    assert verdicts["good"] == {"item": True, "ancestors": True}, verdicts
    assert verdicts["open"] == {"item": True, "ancestors": False}, verdicts
    assert verdicts["link"]["ancestors"] is False, verdicts


@pytest.mark.skipif(os.name != "nt", reason="runs the Windows wrapper")
def test_generic_windows_wrapper_refuses_a_product_version_pin_for_a_staged_setup(tmp_path: Path) -> None:
    # Setup takes no version pin; a -ProductVersion given with -SetupPath
    # used to be accepted and silently ignored.
    engine = _pwsh7()
    assert engine, "Windows CI must provide PowerShell 7"
    result = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(MDM / "windows" / "Invoke-DefenseClawEnterprise.ps1"),
         "-SetupPath", str(tmp_path / "DefenseClawSetup-Enterprise-Standalone-x64.exe"), "-Sha256", "0" * 64,
         "-ProductVersion", "1.4.0"],
        capture_output=True, text=True, timeout=120, check=False,
    )
    document = json.loads([line for line in result.stdout.splitlines() if line.startswith("{")][-1])
    codes = [error["code"] for error in document["errors"]]
    host_refusals = {"mdm_not_elevated", "powershell7_untrusted", "unsupported_architecture", "powershell_constrained_language", "loader_environment_present"}
    if host_refusals.intersection(codes):
        pytest.skip(f"this host cannot run the wrapper: {document['errors'][0]['message']}")
    assert result.returncode == 1639, result.stdout
    assert codes == ["mdm_invalid_arguments"], document
    assert "-ProductVersion applies only to the installed CLI" in document["errors"][0]["message"], document


_PUBLIC_TEXT_PROBE = r"""
$ErrorActionPreference = 'Stop'
__FUNCTION__
$staged = 'C:\Windows\Temp\defenseclaw-mdm-0123456789abcdef0123456789abcdef\config.yaml'
$doc = [ordered]@{
    schema_version = 2
    next_step = "Next step: run DefenseClaw Setup as LocalSystem: DefenseClawSetup-Enterprise-Standalone-x64.exe /ensure CONFIG=$staged JSON=1."
    config = $staged
} | ConvertTo-Json -Compress
[ordered]@{
    plain = ConvertTo-WrapperPublicText -Text $doc -Staged $staged -Public 'C:\Staging\config.yaml'
    spaced = ConvertTo-WrapperPublicText -Text $doc -Staged $staged -Public 'C:\Admin Configs\config.yaml'
    stdin = ConvertTo-WrapperPublicText -Text $doc -Staged $staged -Public ''
    raw = ConvertTo-WrapperPublicText -Text "failed; CONFIG=$staged JSON=1" -Staged $staged -Public 'C:\Staging\config.yaml'
} | ConvertTo-Json -Compress
"""


def test_generic_windows_wrapper_never_names_its_private_config_copy() -> None:
    # WIN-F24: the staging copy is deleted when the wrapper exits, so a
    # next-step command naming it could never be run.
    text = _text(MDM / "windows" / "Invoke-DefenseClawEnterprise.ps1")
    body = text[text.index("function Write-LifecycleResult {") : text.index("\n# --- main")]
    assert "ConvertTo-WrapperPublicText -Text ([string]$Run.StdOut).Trim() -Staged $script:StagedConfig -Public $ConfigPath" in body
    assert "ConvertTo-WrapperPublicText -Text ([string]$Run.StdErr) -Staged $script:StagedConfig -Public $ConfigPath" in body
    assert "$script:StagedConfig = $config" in text


@pytest.mark.skipif(os.name != "nt", reason="runs PowerShell 7")
def test_generic_windows_wrapper_names_the_administrators_config_in_its_result(tmp_path: Path) -> None:
    engine = _pwsh7()
    assert engine, "Windows CI must provide PowerShell 7"
    text = _text(MDM / "windows" / "Invoke-DefenseClawEnterprise.ps1")
    start = text.index("function ConvertTo-WrapperPublicText {")
    function = text[start : text.index("\nfunction Write-LifecycleResult", start)]
    probe = tmp_path / "public-text-probe.ps1"
    probe.write_text(_PUBLIC_TEXT_PROBE.replace("__FUNCTION__", function), encoding="utf-8")
    result = subprocess.run(
        [engine, "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(probe)],
        capture_output=True, text=True, timeout=120, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    out = json.loads(result.stdout.strip().splitlines()[-1])
    plain = json.loads(out["plain"])
    assert "/ensure CONFIG=C:\\Staging\\config.yaml JSON=1" in plain["next_step"], plain
    assert plain["config"] == "C:\\Staging\\config.yaml", plain
    assert "defenseclaw-mdm-" not in out["plain"], out["plain"]
    spaced = json.loads(out["spaced"])
    assert '/ensure CONFIG="C:\\Admin Configs\\config.yaml" JSON=1' in spaced["next_step"], spaced
    stdin = json.loads(out["stdin"])
    assert "/ensure CONFIG=<config.yaml> JSON=1" in stdin["next_step"], stdin
    assert out["raw"] == "failed; CONFIG=C:\\Staging\\config.yaml JSON=1", out["raw"]


def test_windows_scripts_never_concatenate_into_an_argument_list() -> None:
    # PowerShell's comma operator binds tighter than +, so
    # @('/' + $action, 'JSON=1') is the single argument "/ensure JSON=1". The
    # generic wrapper built its Setup command line that way, and Setup refused
    # every -SetupPath run with "unexpected positional argument" (exit 1639).
    pattern = re.compile(r"@\(\s*'[^']*'\s*\+\s*\$\w+\s*,")
    for path in sorted((MDM / "windows").glob("*.ps1")) + sorted((MDM / "intune" / "windows").glob("*.ps1")):
        assert not pattern.search(_text(path)), path.name
    assert "$arguments = @(('/' + $normalizedAction), 'JSON=1')" in _text(
        MDM / "windows" / "Invoke-DefenseClawEnterprise.ps1"
    )


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
