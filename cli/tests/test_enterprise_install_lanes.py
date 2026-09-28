# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""The standalone managed-enterprise install lanes.

On every pull request CI installs the real deb (Ubuntu runner), rpm (RHEL 9
and RHEL 8 containers booted with systemd), macOS pkg (macOS runner) and the
hash-pinned unsigned Windows Setup (Windows runner), then converges, verifies,
detects, uninstalls and checks what is left. These tests pin that wiring and
exercise the result checker every lane relies on; the lanes themselves are
the behavioral check.
"""

from __future__ import annotations

import ast
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CI = ROOT / ".github" / "workflows" / "ci.yml"
RELEASE = ROOT / ".github" / "workflows" / "release.yaml"
SCRIPTS = ROOT / "scripts"
CHECKER = SCRIPTS / "check_enterprise_lifecycle_result.py"
UNIX_LANE = SCRIPTS / "test-enterprise-unix-install.sh"
CONTAINER_LANE = SCRIPTS / "test-enterprise-linux-container.sh"
WINDOWS_LANE = SCRIPTS / "test-enterprise-windows-install.ps1"
WINDOWS_AGENTS = ROOT / "testdata" / "enterprise_install_lane" / "windows-agents.json"
WINDOWS_NATIVE_CI = SCRIPTS / "windows-native-ci.ps1"
SCHEMA = ROOT / "packaging" / "mdm" / "contract" / "lifecycle-result.schema.json"
LANE_JOBS = (
    "enterprise-install-assets",
    "enterprise-linux-install",
    "enterprise-macos-install",
    "enterprise-windows-install",
)
PINNED_ACTION = re.compile(r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")
PINNED_IMAGE = re.compile(r"^registry\.access\.redhat\.com/ubi(8|9)/ubi-init@sha256:[0-9a-f]{64}$")


def _workflow(path: Path) -> dict[str, Any]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    # PyYAML reads the bare `on:` key as the boolean True.
    if True in document:
        document["on"] = document.pop(True)
    return document


def _jobs() -> dict[str, Any]:
    return _workflow(CI)["jobs"]


def _run_text(job: dict[str, Any]) -> str:
    return "\n".join(str(step.get("run", "")) for step in job["steps"])


def _download(job: dict[str, Any]) -> str:
    (step,) = [step for step in job["steps"] if step.get("uses", "").startswith("actions/download-artifact@")]
    return step["with"]["name"]


def test_install_lanes_run_on_every_pull_request() -> None:
    workflow = _workflow(CI)
    trigger = workflow["on"]["pull_request"]
    # A base-branch or path filter would let a pull request to the integration
    # branch merge without the lanes.
    assert not trigger or not set(trigger) & {"branches", "branches-ignore", "paths", "paths-ignore"}
    jobs = workflow["jobs"]
    for name in LANE_JOBS:
        job = jobs[name]
        assert "if" not in job, name
        assert job.get("continue-on-error") is not True, name
        assert isinstance(job.get("timeout-minutes"), int), name
        for step in job["steps"]:
            assert "continue-on-error" not in step, (name, step)
            assert "github.event_name" not in str(step.get("if", "")), (name, step)
            if "uses" in step:
                assert PINNED_ACTION.match(step["uses"]), step["uses"]
            # Pull requests from forks get no secrets; the lanes need none.
            assert "secrets." not in json.dumps(step), (name, step)
    assert jobs["enterprise-linux-install"]["needs"] == "enterprise-install-assets"
    assert jobs["enterprise-windows-install"]["needs"] == "enterprise-install-assets"


def test_linux_lanes_install_the_release_packages_under_systemd() -> None:
    jobs = _jobs()
    assets = jobs["enterprise-install-assets"]
    goreleaser = next(step for step in assets["steps"] if step.get("uses", "").startswith("goreleaser/goreleaser-action@"))
    # The release's own GoReleaser config, run exactly as the Makefile's local
    # snapshot target runs it, with the release's pinned action and version.
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert f"\tgoreleaser {goreleaser['with']['args']}\n" in makefile
    assert "--snapshot" in goreleaser["with"]["args"].split()
    release_steps = [
        step
        for job in _workflow(RELEASE)["jobs"].values()
        for step in job.get("steps", [])
        if step.get("uses", "").startswith("goreleaser/goreleaser-action@")
    ]
    assert release_steps
    for step in release_steps:
        assert step["uses"] == goreleaser["uses"]
        assert step["with"]["version"] == goreleaser["with"]["version"]
    collect = next(step for step in assets["steps"] if step.get("id") == "linux")
    assert "dist/metadata.json" in collect["run"]
    assert assets["outputs"]["linux-version"] == "${{ steps.linux.outputs.version }}"
    uploads = {
        step["with"]["name"]: step["with"]["path"]
        for step in assets["steps"]
        if step.get("uses", "").startswith("actions/upload-artifact@")
    }
    assert uploads == {
        "enterprise-install-linux": "${{ runner.temp }}/enterprise-install-linux/",
        "enterprise-install-windows": "${{ runner.temp }}/enterprise-install-windows/",
    }

    lane = jobs["enterprise-linux-install"]
    assert lane["runs-on"] == "ubuntu-24.04"
    assert lane["strategy"]["fail-fast"] is False
    include = {entry["lane"]: entry for entry in lane["strategy"]["matrix"]["include"]}
    assert set(include) == {"deb", "rpm-el9", "rpm-el8"}
    assert include["deb"]["package"] == "deb" and "image" not in include["deb"]
    for name, major in (("rpm-el9", "9"), ("rpm-el8", "8")):
        assert include[name]["package"] == "rpm"
        assert PINNED_IMAGE.match(include[name]["image"]), include[name]["image"]
        assert f"/ubi{major}/" in include[name]["image"]
    assert lane["env"]["LANE_IMAGE"] == "${{ matrix.image }}"
    assert _download(lane) == "enterprise-install-linux"
    steps = {step.get("if"): str(step.get("run", "")) for step in lane["steps"] if "run" in step}
    deb = steps["matrix.package == 'deb'"]
    rpm = steps["matrix.package == 'rpm'"]
    assert deb.startswith("sudo bash scripts/test-enterprise-unix-install.sh")
    assert 'defenseclaw-enterprise-${LANE_VERSION}-linux-amd64.deb"' in deb
    assert rpm.startswith('bash scripts/test-enterprise-linux-container.sh --image "$LANE_IMAGE"')
    assert 'defenseclaw-enterprise-${LANE_VERSION}-linux-amd64.rpm"' in rpm
    for command in (deb, rpm):
        assert '--version "$LANE_VERSION"' in command


def test_macos_lane_installs_the_unsigned_pkg_under_launchd() -> None:
    lane = _jobs()["enterprise-macos-install"]
    assert lane["runs-on"] == "macos-latest"
    run = _run_text(lane)
    assert 'scripts/build-macos-enterprise-pkg.sh --version 9.9.9 --dist-dir "$RUNNER_TEMP/enterprise-install"' in run
    assert "sudo bash scripts/test-enterprise-unix-install.sh" in run
    assert "defenseclaw-enterprise-9.9.9-darwin-arm64.pkg" in run
    # No signing identity reaches the build, so the pkg and binaries are unsigned.
    assert "SIGN_IDENTITY" not in json.dumps(lane)


def test_windows_lane_installs_the_hash_pinned_unsigned_setup() -> None:
    jobs = _jobs()
    build = next(
        str(step["run"]) for step in jobs["enterprise-install-assets"]["steps"] if "build-setup.sh" in str(step.get("run", ""))
    )
    assert build == 'packaging/windows/standalone/build-setup.sh --version 9.9.9 --out-dir "$RUNNER_TEMP/enterprise-install-windows"'
    # Without --payload-dir or --sign-command the builder embeds the
    # standalone-unsigned payload, which Setup admits by its SHA-256 pins.
    assert "--payload-dir" not in build and "--sign-command" not in build
    lane = jobs["enterprise-windows-install"]
    assert lane["runs-on"] == "windows-latest"
    assert _download(lane) == "enterprise-install-windows"
    step = next(step for step in lane["steps"] if "test-enterprise-windows-install.ps1" in str(step.get("run", "")))
    assert step["shell"] == "pwsh"
    assert "DefenseClawSetup-Enterprise-Standalone-x64.exe" in step["run"]
    assert "-Version 9.9.9" in step["run"]


def test_install_lane_documentation_lists_every_lane() -> None:
    testing = (ROOT / "docs" / "TESTING.md").read_text(encoding="utf-8")
    for script in (UNIX_LANE, CONTAINER_LANE, WINDOWS_LANE, CHECKER):
        assert f"scripts/{script.name}" in testing, script.name


@pytest.mark.parametrize("script", [CHECKER, UNIX_LANE, CONTAINER_LANE, WINDOWS_LANE], ids=lambda path: path.name)
def test_lane_scripts_are_ascii(script: Path) -> None:
    # Windows PowerShell and MDM consoles misread non-ASCII in BOM-less files.
    script.read_bytes().decode("ascii")


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell scripts")
@pytest.mark.parametrize("script", [UNIX_LANE, CONTAINER_LANE, CHECKER], ids=lambda path: path.name)
def test_unix_lane_scripts_are_executable_and_parse(script: Path) -> None:
    assert script.stat().st_mode & stat.S_IXUSR, script.name
    if script.suffix == ".sh":
        subprocess.run(["bash", "-n", str(script)], check=True, capture_output=True, text=True)
        # macOS runs the lane with its /bin/bash 3.2 under sudo.
        if Path("/bin/bash").exists():
            subprocess.run(["/bin/bash", "-n", str(script)], check=True, capture_output=True, text=True)


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell scripts")
def test_unix_lane_requires_its_arguments() -> None:
    result = subprocess.run(["bash", str(UNIX_LANE)], capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 2
    assert "usage:" in result.stderr


@pytest.mark.skipif(os.name == "nt" or os.geteuid() == 0, reason="needs a non-root POSIX user")
def test_unix_lane_refuses_to_run_without_root(tmp_path: Path) -> None:
    package = tmp_path / "defenseclaw-enterprise-1.0.0-linux-amd64.deb"
    package.write_bytes(b"")
    results = tmp_path / "results"
    result = subprocess.run(
        ["bash", str(UNIX_LANE), "--package", str(package), "--version", "1.0.0", "--results", str(results)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 1
    assert "run as root on a disposable host" in result.stderr
    assert not results.exists()


def test_windows_lane_parses() -> None:
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("pwsh is not installed")
    command = (
        "$tokens = $null; $errors = $null; "
        "[void][Management.Automation.Language.Parser]::ParseFile($args[0], [ref]$tokens, [ref]$errors); "
        "foreach ($e in $errors) { [Console]::Error.WriteLine($e.ToString()) }; exit $errors.Count"
    )
    result = subprocess.run(
        [pwsh, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", command, str(WINDOWS_LANE)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stderr


# ---- the lifecycle result checker --------------------------------------------


def _result(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": 2,
        "ok": True,
        "action": "ensure",
        "noop": False,
        "profile": "standalone",
        "platform": "linux",
        "product_version": "1.4.0",
        "installed_version": "1.4.0",
        "installed": True,
        "transaction_pending": False,
        "services": [
            {"name": "defenseclaw-gateway.service", "kind": "gateway", "state": "active/running", "required": True},
            {"name": "defenseclaw-enterprise-verify.timer", "kind": "timer", "state": "active/waiting", "required": True},
            {"name": "defenseclaw-enterprise-verify.service", "kind": "oneshot", "state": "inactive/dead", "required": False},
        ],
        "readiness": {"gateway": True, "guardian": True, "enumerator": True, "sensor_helper": True},
        "inspection": {"local": "active", "ai_defense": "disabled"},
        "machine_policy": {
            "codex": {"ownership": "merge", "lock": "enforce", "effective_lock": "enforce", "owned_entries": 10, "foreign_entries": 0},
        },
        "enrollment": {"targets": 0, "pending": 0, "failed": 0, "exempt": 0},
        "coverage_complete": True,
        "security_complete": True,
        "errors": [],
        "warnings": [],
        "exit_code": 0,
    }
    document.update(overrides)
    return document


def _check(tmp_path: Path, document: Any, *arguments: str, raw: bytes | None = None) -> subprocess.CompletedProcess[str]:
    path = tmp_path / "result.json"
    path.write_bytes(raw if raw is not None else json.dumps(document).encode("utf-8"))
    return subprocess.run(
        [sys.executable, str(CHECKER), str(path), "--label", "step", *arguments],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )


FULL = ("--action", "ensure", "--platform", "linux", "--changed", "--installed", "--version", "1.4.0", "--ready")


def test_checker_fixture_follows_the_lifecycle_schema() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8"))).validate(_result())


def test_checker_required_keys_match_the_schema() -> None:
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    tree = ast.parse(CHECKER.read_text(encoding="utf-8"))
    required = next(
        ast.literal_eval(node.value)
        for node in tree.body
        if isinstance(node, ast.Assign) and any(getattr(target, "id", "") == "REQUIRED_KEYS" for target in node.targets)
    )
    assert list(required) == schema["required"]


def test_checker_stays_python_36_compatible() -> None:
    # The RHEL 8 lane runs it with /usr/libexec/platform-python 3.6.
    source = CHECKER.read_text(encoding="utf-8")
    ast.parse(source, feature_version=(3, 6))
    assert "from __future__ import annotations" not in source


def test_checker_accepts_a_matching_result(tmp_path: Path) -> None:
    result = _check(
        tmp_path,
        _result(),
        *FULL,
        "--complete",
        "--machine-policy",
        "codex",
        "--machine-policy-enforced",
        "codex",
        "--machine-policy-target",
        "codex",
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.startswith("ok   step: action=ensure ok=True noop=False installed=True installed_version=1.4.0")
    assert "coverage_complete=True security_complete=True" in result.stdout


def test_checker_accepts_only_the_warnings_a_step_allows(tmp_path: Path) -> None:
    document = _result(warnings=[{"code": "unprivileged_user_namespaces", "message": "kernel setting"}])
    assert _check(tmp_path, document, *FULL, "--allow-warning", "unprivileged_user_namespaces").returncode == 0
    result = _check(tmp_path, document, *FULL, "--allow-warning", "ensure_install")
    assert result.returncode == 1
    assert "  - unexpected warning unprivileged_user_namespaces" in result.stderr.splitlines()
    assert "  warning: unprivileged_user_namespaces: kernel setting" in result.stderr.splitlines()


def test_checker_accepts_a_windows_result_before_the_claude_proof(tmp_path: Path) -> None:
    # Windows keeps security_complete false until the attested live Claude
    # Code policy proof; Claude Code then has a target but no effective lock.
    document = _result(
        platform="windows",
        security_complete=False,
        machine_policy={
            "codex": {"ownership": "merge", "lock": "enforce", "effective_lock": "enforce", "owned_entries": 0, "foreign_entries": 0},
            "claudecode": {"ownership": "merge", "lock": "enforce", "owned_entries": 0, "foreign_entries": 0},
        },
        warnings=[{"code": "ensure_install", "message": "ensure ran install: not_installed"}],
    )
    arguments = (
        "--coverage-complete",
        "--security-incomplete",
        "--machine-policy-enforced",
        "codex",
        "--machine-policy-target",
        "claudecode",
        "--allow-warning",
        "ensure_install",
    )
    result = _check(tmp_path, document, "--platform", "windows", *arguments)
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("overrides", "arguments", "problem"),
    [
        ({"ok": False, "errors": [{"code": "activation_failed", "message": "gateway did not become ready"}]}, FULL, "ok is false"),
        ({"errors": [{"code": "verify_failed", "message": "x"}]}, FULL, "1 error(s) reported"),
        ({"exit_code": 1}, FULL, "exit_code is 1"),
        ({"transaction_pending": True}, FULL, "a transaction is still pending"),
        ({"profile": "secure_client"}, FULL, "profile is 'secure_client', want 'standalone'"),
        ({"action": "install"}, FULL, "action is 'install', want 'ensure'"),
        ({"platform": "darwin"}, FULL, "platform is 'darwin', want 'linux'"),
        ({"noop": True, "noop_reason": "up_to_date"}, FULL, "noop is true (up_to_date), want a change"),
        ({}, ("--noop",), "noop is false, want a no-op"),
        ({"installed": False}, FULL, "installed is false"),
        ({}, ("--not-installed",), "installed is true, want not installed"),
        ({"installed_version": "1.3.9"}, FULL, "installed_version is '1.3.9', want '1.4.0'"),
        ({}, ("--product-version", "1.5.0"), "product_version is '1.4.0', want '1.5.0'"),
        (
            {"readiness": {"gateway": True, "guardian": False, "enumerator": True, "sensor_helper": True}},
            FULL,
            "readiness.guardian is false",
        ),
        (
            {"services": [{"name": "defenseclaw-hook-guardian.service", "kind": "guardian", "state": "failed/failed", "required": True}]},
            FULL,
            "required service defenseclaw-hook-guardian.service is 'failed/failed'",
        ),
        ({"machine_policy": {}}, ("--machine-policy", "claudecode"), "machine_policy has no claudecode entry"),
        ({"machine_policy": {}}, ("--machine-policy-target", "claudecode"), "machine_policy has no claudecode entry"),
        ({"machine_policy": {}}, ("--machine-policy-enforced", "codex"), "machine_policy has no codex entry"),
        (
            {"machine_policy": {"codex": {"ownership": "merge", "lock": "enforce", "owned_entries": 10, "foreign_entries": 0}}},
            ("--machine-policy-enforced", "codex"),
            "machine_policy.codex.effective_lock is None, want 'enforce'",
        ),
        (
            {"machine_policy": {"codex": {"ownership": "merge", "effective_lock": "preserve", "owned_entries": 10, "foreign_entries": 0}}},
            ("--machine-policy-enforced", "codex"),
            "machine_policy.codex.effective_lock is 'preserve', want 'enforce'",
        ),
        # ok only means "no errors": the lifecycle reports a failed guardian
        # target, an unverified hook contract and a rejected config as
        # warnings, with security_complete false.
        (
            {"security_complete": False, "warnings": [{"code": "guardian_target_failed", "message": "1 of 2 targets failed"}]},
            FULL,
            "unexpected warning guardian_target_failed",
        ),
        ({"security_complete": False}, FULL + ("--complete",), "security_complete is false"),
        ({"coverage_complete": False}, FULL + ("--complete",), "coverage_complete is false"),
        ({"coverage_complete": False}, ("--coverage-complete",), "coverage_complete is false"),
        ({}, ("--security-incomplete",), "security_complete is true, want false"),
        ({"warnings": [{"code": "config_rejected", "message": "x"}]}, ("--installed",), "unexpected warning config_rejected"),
        (
            {"machine_policy": {"codex": {"ownership": "merge", "owned_entries": 0, "foreign_entries": 0}}},
            ("--machine-policy", "codex"),
            "machine_policy.codex owns no entries",
        ),
        ({"schema_version": 1}, FULL, "schema_version is 1, want 2"),
    ],
)
def test_checker_rejects_a_result_that_does_not_match(
    tmp_path: Path, overrides: dict[str, Any], arguments: tuple[str, ...], problem: str
) -> None:
    result = _check(tmp_path, _result(**overrides), *arguments)
    assert result.returncode == 1, result.stdout
    assert f"  - {problem}" in result.stderr.splitlines(), result.stderr
    assert result.stderr.startswith("FAIL step: ")


def test_checker_prints_the_lifecycle_errors_on_failure(tmp_path: Path) -> None:
    document = _result(ok=False, exit_code=1, errors=[{"code": "verify_failed", "message": "defenseclaw-hook-guardian.service is not active"}])
    result = _check(tmp_path, document, "--installed")
    assert result.returncode == 1
    assert "  error: verify_failed: defenseclaw-hook-guardian.service is not active" in result.stderr


@pytest.mark.parametrize("missing", ["readiness", "services", "errors", "exit_code"])
def test_checker_rejects_a_result_missing_a_required_key(tmp_path: Path, missing: str) -> None:
    document = _result()
    del document[missing]
    result = _check(tmp_path, document)
    assert result.returncode == 1
    assert f"  - missing key {missing!r}" in result.stderr.splitlines()


@pytest.mark.parametrize("state", ["active/running", "active/waiting", "running", "Running"])
def test_checker_accepts_every_service_manager_running_state(tmp_path: Path, state: str) -> None:
    document = _result(services=[{"name": "DefenseClawGateway", "kind": "gateway", "state": state, "required": True}])
    assert _check(tmp_path, document, "--ready").returncode == 0


@pytest.mark.parametrize(
    "raw",
    [b"", b"   \n", b"[]", b'{"schema_version": 2} trailing', b"lifecycle: starting\n{}", b"\xff\xfe{}"],
    ids=["empty", "blank", "array", "trailing-text", "leading-text", "not-utf8"],
)
def test_checker_refuses_output_that_is_not_one_json_object(tmp_path: Path, raw: bytes) -> None:
    result = _check(tmp_path, None, raw=raw)
    assert result.returncode == 2
    assert "FAIL step: cannot read the lifecycle result" in result.stderr


def test_checker_tolerates_a_utf8_byte_order_mark(tmp_path: Path) -> None:
    raw = b"\xef\xbb\xbf" + json.dumps(_result()).encode("utf-8") + b"\r\n"
    assert _check(tmp_path, None, *FULL, raw=raw).returncode == 0


@pytest.mark.parametrize("arguments", [("--noop", "--changed"), ("--complete", "--security-incomplete")])
def test_checker_refuses_contradictory_expectations(tmp_path: Path, arguments: tuple[str, ...]) -> None:
    result = _check(tmp_path, _result(), *arguments)
    assert result.returncode == 2
    assert "not allowed with argument" in result.stderr


# ---- what each lane step requires --------------------------------------------


def _unix_checks() -> dict[str, str]:
    """The Unix lane's check calls by label, continuation lines joined."""
    text = UNIX_LANE.read_text(encoding="utf-8").replace("\\\n", " ")
    checks = {}
    for line in text.splitlines():
        match = re.match(r'^\s*check "\$results/[\w-]+\.json" ([\w-]+) (.*)$', line)
        if match:
            checks[match.group(1)] = match.group(2)
    return checks


def test_unix_lane_requires_complete_coverage_and_security_while_installed() -> None:
    checks = _unix_checks()
    assert set(checks) == {"package-install", "ensure-config", "ensure-noop", "verify", "status", "uninstall", "purge"}
    for label in ("package-install", "ensure-config", "ensure-noop", "verify", "status"):
        assert " --complete" in checks[label], label
    for label in ("uninstall", "purge"):
        assert "--complete" not in checks[label], label


def test_unix_lane_allows_only_the_host_user_namespace_warning() -> None:
    checks = _unix_checks()
    allowed = {label: re.findall(r"--allow-warning (\S+)", arguments) for label, arguments in checks.items()}
    assert allowed == {label: (["unprivileged_user_namespaces"] if label == "verify" else []) for label in checks}


def test_unix_lane_requires_owned_and_locked_machine_policy() -> None:
    text = UNIX_LANE.read_text(encoding="utf-8")
    policy = re.search(r"^policy_checks=\((.*?)\)$", text, re.MULTILINE | re.DOTALL)
    assert policy is not None
    assert policy.group(1).split() == [
        "--machine-policy",
        "claudecode",
        "--machine-policy",
        "codex",
        "--machine-policy-enforced",
        "claudecode",
        "--machine-policy-enforced",
        "codex",
    ]
    checks = _unix_checks()
    for label in ("ensure-config", "verify", "status"):
        assert '"${policy_checks[@]}"' in checks[label], label


def _windows_assertions() -> dict[str, str]:
    """The Windows lane's Assert-Result calls by label, continuation lines joined."""
    text = re.sub(r"\+\n\s*", "+ ", WINDOWS_LANE.read_text(encoding="utf-8"))
    assertions = {}
    for line in text.splitlines():
        match = re.match(r"^\s*Assert-Result \$run '([\w-]+)' (.*)$", line)
        if match:
            assertions[match.group(1)] = match.group(2)
    return assertions


def test_windows_lane_checks_the_machine_policy_of_both_connectors() -> None:
    text = WINDOWS_LANE.read_text(encoding="utf-8")
    installed = re.search(r"^\$installedChecks = @\((.*?)^\)$", text, re.MULTILINE | re.DOTALL)
    assert installed is not None
    assert re.findall(r"'([^']+)'", installed.group(1)) == [
        "--coverage-complete",
        "--security-incomplete",
        "--machine-policy-enforced",
        "codex",
        "--machine-policy-target",
        "claudecode",
    ]
    assertions = _windows_assertions()
    assert set(assertions) == {"setup-ensure-install", "setup-ensure-noop", "verify", "status", "cli-ensure", "setup-uninstall"}
    for label in ("setup-ensure-install", "setup-ensure-noop", "verify", "status", "cli-ensure"):
        assert "$installedChecks" in assertions[label], label
    assert "$installedChecks" not in assertions["setup-uninstall"]
    allowed = {label: re.findall(r"'--allow-warning', '([^']+)'", arguments) for label, arguments in assertions.items()}
    assert allowed == {label: (["ensure_install"] if label == "setup-ensure-install" else []) for label in assertions}
    # The files themselves: applied after the first ensure, gone after uninstall.
    body = text[text.index("Step 'Setup /ensure with an administrator config") :]
    assert body.index("Assert-PolicyApplied") < body.index("Step 'Setup /ensure again")
    uninstall = body[body.index("Step 'Setup /uninstall'") :]
    assert "Assert-PolicyGone 'after uninstall'" in uninstall
    preflight = text[text.index("Step 'preflight") : text.index("Step 'Setup /ensure with")]
    assert "Get-PolicyArtifacts" in preflight
    assert "'ClaudeCode\\managed-settings.d'" in text and "'OpenAI\\Codex'" in text


def test_windows_lane_stages_an_agent_for_every_connector_it_enables() -> None:
    text = WINDOWS_LANE.read_text(encoding="utf-8")
    config = re.search(r"'  connectors:'(.*?)\) -join", text, re.DOTALL)
    assert config is not None
    enabled = re.findall(r"'    (\w+):'", config.group(1))
    agents = json.loads(WINDOWS_AGENTS.read_text(encoding="utf-8"))["agents"]
    assert sorted(agent["connector"] for agent in agents) == sorted(enabled) == ["claudecode", "codex"]
    assert "testdata\\enterprise_install_lane\\windows-agents.json" in text
    # The fixture must sit where the standalone enumerator probes a profile
    # (internal/enterprisehooks/agent_version_windows.go).
    assert "'AppData\\Roaming\\npm\\node_modules\\'" in text
    # Each claim is a pinned release client, so a real user could run it.
    native = WINDOWS_NATIVE_CI.read_text(encoding="utf-8")
    for agent in agents:
        spec = re.search(
            r"Connector = '" + re.escape(agent["connector"]) + r"'\s+Version = '([^']+)'\s+Package = '([^']+)'", native
        )
        assert spec is not None, agent["connector"]
        assert (agent["version"], agent["package"]) == (spec.group(1), spec.group(2))


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell scripts")
def test_unit_check_fails_on_diagnostics_outside_the_allow_list(tmp_path: Path) -> None:
    """The lane's unit check fails on a directive the systemd 239 allow list does not name."""
    bin_dir, unit_dir = tmp_path / "bin", tmp_path / "units"
    bin_dir.mkdir()
    unit_dir.mkdir()
    output = tmp_path / "verify-output.txt"
    output.write_text(
        "/usr/lib/systemd/system/defenseclaw-gateway.service:70: Unknown lvalue 'ProtectNew' in section 'Service'\n",
        encoding="utf-8",
    )
    fakes = {
        "systemctl": '#!/bin/sh\necho "systemd 239 (239-1.test)"\necho "+PAM +AUDIT"\n',
        "systemd-analyze": f"#!/bin/sh\ncat {shlex.quote(str(output))} >&2\n",
    }
    for name, body in fakes.items():
        fake = bin_dir / name
        fake.write_text(body, encoding="utf-8")
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    for unit in ("defenseclaw-gateway.service", "defenseclaw-enterprise-apply.path", "defenseclaw.conf"):
        (unit_dir / unit).write_text("", encoding="utf-8")
    text = UNIX_LANE.read_text(encoding="utf-8")
    functions = "".join(
        re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", text, re.MULTILINE | re.DOTALL).group(0)
        for name in ("die", "directive_minimum", "unit_diagnostics")
    )
    harness = "\n".join(
        [
            "set -euo pipefail",
            f"PATH={shlex.quote(str(bin_dir))}:$PATH",
            f"unit_dir={shlex.quote(str(unit_dir))}",
            functions,
            "unit_diagnostics",
            "echo UNITS-PASSED",
        ]
    )
    result = subprocess.run(["bash", "-c", harness], capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 1, result.stdout
    assert "UNITS-PASSED" not in result.stdout
    assert "unit diagnostics outside the systemd 239 allow list" in result.stderr
