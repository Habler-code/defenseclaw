# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""CI gates for the standalone managed-enterprise build.

These tests pin the wiring of the checks that keep the enterprise binaries,
packages and lanes honest: the binaries start without stray stderr output,
the macOS lifecycle job runs the darwin code paths, the install lanes compare
the lifecycle's process status with its JSON result and check how the
packaged units load, and one aggregate job fails when any of them fails.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
CI = ROOT / ".github" / "workflows" / "ci.yml"
MAKEFILE = ROOT / "Makefile"
UNIX_LANE = ROOT / "scripts" / "test-enterprise-unix-install.sh"
CHECKER = ROOT / "scripts" / "check_enterprise_lifecycle_result.py"


def _workflow(path: Path) -> dict[str, Any]:
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    # PyYAML reads the bare `on:` key as the boolean True.
    if True in document:
        document["on"] = document.pop(True)
    return document


def _jobs() -> dict[str, Any]:
    return _workflow(CI)["jobs"]


def _make_variable(name: str) -> list[str]:
    text = MAKEFILE.read_text(encoding="utf-8").replace("\\\n", " ")
    match = re.search(rf"^{name} :=(.*)$", text, re.MULTILINE)
    assert match is not None, name
    return match.group(1).split()


# ---- start-up output ---------------------------------------------------------


def test_quiet_startup_check_covers_the_gateway_hook_and_sensor_helper() -> None:
    commands = {spec.split(":")[0]: spec for spec in _make_variable("QUIET_STARTUP_COMMANDS")}
    assert commands["defenseclaw-gateway"] == "defenseclaw-gateway:./cmd/defenseclaw:--version"
    assert commands["defenseclaw-hook"] == "defenseclaw-hook:./cmd/defenseclaw-hook:--version-json"
    assert commands["defenseclaw-sensor-helper"] == (
        "defenseclaw-sensor-helper:./cmd/defenseclaw-sensor-helper:--version"
    )
    for spec in commands.values():
        _, package, argument = spec.split(":")
        assert (ROOT / package).is_dir(), spec
        assert argument.startswith("--"), spec


def test_quiet_startup_check_runs_on_linux_and_macos() -> None:
    job = _jobs()["unix-standalone-lifecycle"]
    assert set(job["strategy"]["matrix"]["os"]) == {"ubuntu-24.04", "macos-latest"}
    (step,) = [step for step in job["steps"] if step.get("run") == "make check-quiet-startup"]
    assert "if" not in step and "continue-on-error" not in step


# ---- lifecycle process status in the Unix lane --------------------------------

LANE_HELPERS = ("die", "check", "exit_status_matches", "lifecycle", "run_lifecycle")


def _lane_helpers(names: tuple[str, ...] = LANE_HELPERS) -> str:
    """The Unix lane's shell functions of these names, as the script defines them."""
    text = UNIX_LANE.read_text(encoding="utf-8")
    blocks = []
    for name in names:
        match = re.search(rf"^{name}\(\) \{{\n.*?^\}}\n", text, re.MULTILINE | re.DOTALL)
        if match:
            blocks.append(match.group(0))
    return "".join(blocks)


def _verify_result() -> dict[str, Any]:
    return {
        "schema_version": 2,
        "ok": True,
        "action": "verify",
        "noop": False,
        "profile": "standalone",
        "platform": "linux",
        "product_version": "1.4.0",
        "installed_version": "1.4.0",
        "installed": True,
        "transaction_pending": False,
        "services": [
            {"name": "defenseclaw-gateway.service", "kind": "gateway", "state": "active/running", "required": True},
        ],
        "readiness": {"gateway": True, "guardian": True, "enumerator": True, "sensor_helper": True},
        "inspection": {"local": "active", "ai_defense": "disabled"},
        "machine_policy": {},
        "enrollment": {"targets": 0, "pending": 0, "failed": 0, "exempt": 0},
        "coverage_complete": True,
        "security_complete": True,
        "errors": [],
        "warnings": [],
        "exit_code": 0,
    }


def _run_lane_verify_step(tmp_path: Path, process_status: int) -> subprocess.CompletedProcess[str]:
    """Run the lane's verify step against a gateway that prints a passing
    result and then exits with process_status."""
    results = tmp_path / "results"
    results.mkdir()
    payload = tmp_path / "result.json"
    payload.write_text(json.dumps(_verify_result()), encoding="utf-8")
    gateway = tmp_path / "defenseclaw-gateway"
    gateway.write_text(f"#!/bin/sh\ncat {shlex.quote(str(payload))}\nexit {process_status}\n", encoding="utf-8")
    gateway.chmod(gateway.stat().st_mode | stat.S_IXUSR)
    harness = "\n".join(
        [
            "set -euo pipefail",
            "platform=linux",
            f"python={shlex.quote(sys.executable)}",
            f"checker={shlex.quote(str(CHECKER))}",
            f"results={shlex.quote(str(results))}",
            f"gateway={shlex.quote(str(gateway))}",
            _lane_helpers(),
            "lifecycle 04-verify verify",
            'check "$results/04-verify.json" verify --action verify --installed --version 1.4.0 --ready',
            "echo STEP-PASSED",
        ]
    )
    return subprocess.run(["bash", "-c", harness], capture_output=True, text=True, timeout=60, check=False)


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell scripts")
def test_unix_lane_step_passes_when_the_process_and_result_agree(tmp_path: Path) -> None:
    result = _run_lane_verify_step(tmp_path, 0)
    assert result.returncode == 0, result.stderr
    assert "STEP-PASSED" in result.stdout
    assert (tmp_path / "results" / "04-verify.rc").read_text(encoding="utf-8").strip() == "0"


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell scripts")
def test_unix_lane_step_fails_when_the_process_exits_non_zero_after_a_passing_result(tmp_path: Path) -> None:
    # MDM scripts act on the process status: a passing JSON result from a
    # process that then exits 3 is a failed step, as in the Windows lane.
    result = _run_lane_verify_step(tmp_path, 3)
    assert result.returncode == 1, result.stdout
    assert "STEP-PASSED" not in result.stdout
    assert "verify: the lifecycle process exited 3, its result reports exit_code 0" in result.stderr


def test_unix_lane_purge_keeps_the_process_status() -> None:
    text = UNIX_LANE.read_text(encoding="utf-8")
    purge = text[text.index("# ---- purge") :]
    purge = purge[: purge.index("\nfor dir in")]
    assert 'run_lifecycle "$stage/defenseclaw-gateway" 07-purge uninstall --purge' in purge
    assert "|| true" not in purge


# ---- unit-load diagnostics in the Linux lanes ---------------------------------

# What systemd-analyze verify prints for the packaged units on RHEL 8
# (systemd 239-82.el8_10.19, the rpm-el8 lane's pinned ubi8-init image).
EL8_VERIFY_OUTPUT = "".join(
    f"/usr/lib/systemd/system/./defenseclaw-{unit}:{line}: Unknown lvalue '{directive}' in section '{section}'\n"
    for unit, line, directive, section in (
        ("gateway.service", 58, "ProtectClock", "Service"),
        ("gateway.service", 60, "ProtectHostname", "Service"),
        ("gateway.service", 61, "ProtectKernelLogs", "Service"),
        ("gateway.service", 64, "ProtectProc", "Service"),
        ("gateway.service", 65, "ProcSubset", "Service"),
        ("hook-guardian.service", 40, "ProtectProc", "Service"),
        ("enterprise-apply.path", 14, "TriggerLimitIntervalSec", "Path"),
        ("enterprise-apply.path", 15, "TriggerLimitBurst", "Path"),
    )
)


def _run_unit_diagnostics(
    tmp_path: Path, systemd_version: int, verify_output: str, verify_status: int = 0
) -> subprocess.CompletedProcess[str]:
    """Run the lane's unit_diagnostics against a fake systemctl and
    systemd-analyze that report systemd_version and verify_output."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    output = tmp_path / "verify-output.txt"
    output.write_text(verify_output, encoding="utf-8")
    fakes = {
        "systemctl": f'#!/bin/sh\necho "systemd {systemd_version} ({systemd_version}-1.test)"\necho "+PAM +AUDIT"\n',
        "systemd-analyze": f"#!/bin/sh\ncat {shlex.quote(str(output))} >&2\nexit {verify_status}\n",
    }
    for name, body in fakes.items():
        fake = bin_dir / name
        fake.write_text(body, encoding="utf-8")
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    unit_dir = tmp_path / "units"
    unit_dir.mkdir()
    for unit in ("defenseclaw-gateway.service", "defenseclaw-enterprise-apply.path", "defenseclaw.conf"):
        (unit_dir / unit).write_text("", encoding="utf-8")
    harness = "\n".join(
        [
            "set -euo pipefail",
            f"PATH={shlex.quote(str(bin_dir))}:$PATH",
            f"unit_dir={shlex.quote(str(unit_dir))}",
            _lane_helpers(("die", "directive_minimum", "unit_diagnostics")),
            "unit_diagnostics",
            "echo UNITS-PASSED",
        ]
    )
    return subprocess.run(["bash", "-c", harness], capture_output=True, text=True, timeout=60, check=False)


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell scripts")
def test_unit_check_accepts_the_directives_rhel8_is_known_to_ignore(tmp_path: Path) -> None:
    result = _run_unit_diagnostics(tmp_path, 239, EL8_VERIFY_OUTPUT)
    assert result.returncode == 0, result.stderr
    assert "UNITS-PASSED" in result.stdout
    assert "2 DefenseClaw units load on systemd 239" in result.stdout
    # The lane log names what the older systemd drops from the sandbox.
    for ignored in (
        "Service.ProtectHostname (systemd 242)",
        "Service.ProtectKernelLogs (systemd 244)",
        "Service.ProtectClock (systemd 245)",
        "Service.ProtectProc (systemd 247)",
        "Service.ProcSubset (systemd 247)",
        "Path.TriggerLimitIntervalSec (systemd 250)",
        "Path.TriggerLimitBurst (systemd 250)",
    ):
        assert f"  {ignored}\n" in result.stdout, ignored


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell scripts")
def test_unit_check_reads_each_systemd_message_format(tmp_path: Path) -> None:
    # systemd 239 says "Unknown lvalue 'X' in section 'S'"; later releases say
    # "Unknown key name 'X' in section 'S'" or "Unknown key 'X' in section [S]".
    output = (
        "/usr/lib/systemd/system/defenseclaw-gateway.service:58: "
        "Unknown key name 'ProtectProc' in section 'Service', ignoring.\n"
        "/usr/lib/systemd/system/defenseclaw-enterprise-apply.path:14: "
        "Unknown key 'TriggerLimitBurst' in section [Path], ignoring.\n"
    )
    result = _run_unit_diagnostics(tmp_path, 246, output)
    assert result.returncode == 0, result.stderr
    assert "  Service.ProtectProc (systemd 247)\n" in result.stdout
    assert "  Path.TriggerLimitBurst (systemd 250)\n" in result.stdout


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell scripts")
def test_unit_check_is_clean_on_a_current_systemd(tmp_path: Path) -> None:
    # A warning about another unit (not DefenseClaw's) is not the lane's to judge.
    result = _run_unit_diagnostics(tmp_path, 255, "/etc/systemd/system/other.service:3: Unknown key name 'X'\n")
    assert result.returncode == 0, result.stderr
    assert "2 DefenseClaw units load on systemd 255" in result.stdout
    assert "ignores" not in result.stdout


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell scripts")
@pytest.mark.parametrize(
    ("systemd_version", "verify_output"),
    [
        # A systemd that has the directive must not report it unknown.
        (252, EL8_VERIFY_OUTPUT),
        (
            255,
            "/usr/lib/systemd/system/defenseclaw-gateway.service:58: "
            "Unknown key name 'ProtectClock' in section 'Service', ignoring.\n",
        ),
        (
            252,
            "/usr/lib/systemd/system/defenseclaw-enterprise-apply.path:14: "
            "Unknown key 'TriggerLimitBurst' in section [Path], ignoring.\n",
        ),
        # A directive outside the allow list, or one in another section.
        (
            239,
            "/usr/lib/systemd/system/defenseclaw-gateway.service:70: "
            "Unknown lvalue 'ProtectNew' in section 'Service'\n",
        ),
        (
            239,
            "/usr/lib/systemd/system/defenseclaw-gateway.socket:9: "
            "Unknown lvalue 'ProtectClock' in section 'Socket'\n",
        ),
        # Any other diagnostic about a DefenseClaw unit.
        (255, "defenseclaw-gateway.service: Command /opt/defenseclaw/bin/defenseclaw-gateway is not executable\n"),
    ],
    ids=["el8-output-on-252", "known-key-255", "path-limit-on-252", "unlisted", "wrong-section", "other-diagnostic"],
)
def test_unit_check_fails_on_diagnostics_outside_the_allow_list(
    tmp_path: Path, systemd_version: int, verify_output: str
) -> None:
    result = _run_unit_diagnostics(tmp_path, systemd_version, verify_output)
    assert result.returncode == 1, result.stdout
    assert "UNITS-PASSED" not in result.stdout
    assert f"unit diagnostics outside the systemd {systemd_version} allow list" in result.stderr


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell scripts")
def test_unit_check_fails_when_verify_fails(tmp_path: Path) -> None:
    result = _run_unit_diagnostics(tmp_path, 239, "", verify_status=1)
    assert result.returncode == 1, result.stdout
    assert "systemd-analyze verify exited 1 on systemd 239" in result.stderr


def test_linux_lanes_check_the_units_after_install() -> None:
    text = UNIX_LANE.read_text(encoding="utf-8")
    install = text[text.index("# ---- install") : text.index("# ---- reconfigure")]
    assert 'if [ "$platform" = linux ]; then\n' in install
    assert install.rstrip().endswith("unit_diagnostics\nfi")
    assert "    unit_dir=/usr/lib/systemd/system\n" in text
    # The rpm-el8 lane (systemd 239) runs the lane script in its container.
    lanes = {entry["lane"]: entry for entry in _jobs()["enterprise-linux-install"]["strategy"]["matrix"]["include"]}
    assert "/ubi8/" in lanes["rpm-el8"]["image"]
    container = (ROOT / "scripts" / "test-enterprise-linux-container.sh").read_text(encoding="utf-8")
    assert "bash /src/scripts/test-enterprise-unix-install.sh" in container


# ---- one required check for the enterprise gates ------------------------------

ENTERPRISE_GATES = (
    "enterprise-install-assets",
    "enterprise-linux-install",
    "enterprise-macos-install",
    "enterprise-windows-install",
    "unix-standalone-lifecycle",
    "secure-client-golden",
)


def _run_enterprise_required(results: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Run the aggregate job's step with each gate's result as GitHub
    Actions would substitute it."""
    (step,) = _jobs()["enterprise-required"]["steps"]
    environment = dict(os.environ)
    for variable, expression in step["env"].items():
        match = re.fullmatch(r"\$\{\{ needs\.([\w-]+)\.result \}\}", expression)
        assert match is not None, (variable, expression)
        environment[variable] = results[match.group(1)]
    return subprocess.run(
        ["bash", "-c", step["run"]], env=environment, capture_output=True, text=True, timeout=60, check=False
    )


def test_enterprise_required_needs_every_enterprise_gate() -> None:
    jobs = _jobs()
    job = jobs["enterprise-required"]
    assert job["name"] == "Enterprise Required"
    assert job["needs"] == list(ENTERPRISE_GATES)
    # It must run, and fail, when a gate fails or is skipped.
    assert job["if"] == "${{ always() }}"
    assert job.get("continue-on-error") is not True
    for gate in ENTERPRISE_GATES:
        assert gate in jobs, gate
    # Every install lane is a gate.
    lanes = {name for name, lane in jobs.items() if str(lane.get("name", "")).startswith("Enterprise Install Lane")}
    assert lanes <= set(ENTERPRISE_GATES)
    (step,) = job["steps"]
    gated = set()
    for expression in step["env"].values():
        match = re.fullmatch(r"\$\{\{ needs\.([\w-]+)\.result \}\}", expression)
        assert match is not None, expression
        gated.add(match.group(1))
    assert gated == set(ENTERPRISE_GATES)


@pytest.mark.skipif(os.name == "nt", reason="bash step")
def test_latest_go_quiet_startup_check_is_advisory() -> None:
    jobs = _jobs()
    job = jobs["quiet-startup-latest-go"]
    assert job["continue-on-error"] is True
    (setup,) = [step for step in job["steps"] if str(step.get("uses", "")).startswith("actions/setup-go@")]
    assert setup["with"] == {"go-version": "stable"}
    (step,) = [step for step in job["steps"] if step.get("run") == "make check-quiet-startup"]
    assert step["env"]["GOTOOLCHAIN"] == "local"
    assert "quiet-startup-latest-go" not in jobs["enterprise-required"]["needs"]


def test_enterprise_required_passes_only_when_every_gate_succeeded() -> None:
    passing = dict.fromkeys(ENTERPRISE_GATES, "success")
    result = _run_enterprise_required(passing)
    assert result.returncode == 0, result.stdout + result.stderr
    for gate in ENTERPRISE_GATES:
        for outcome in ("failure", "cancelled", "skipped"):
            result = _run_enterprise_required({**passing, gate: outcome})
            assert result.returncode == 1, (gate, outcome, result.stdout)
            assert f": {outcome}\n" in result.stdout


# ---- darwin code paths on the macOS lifecycle leg -----------------------------


def _macos_darwin_step() -> dict[str, Any]:
    job = _jobs()["unix-standalone-lifecycle"]
    (step,) = [step for step in job["steps"] if "./internal/agentprocess/..." in str(step.get("run", ""))]
    return step


def _selected_tests(package: str) -> set[str]:
    """The Test functions the macOS step selects in package, by running its
    selection function over the checkout."""
    run = _macos_darwin_step()["run"]
    function = re.search(r"^unix_tests\(\) \{.*?^\}$", run, re.MULTILINE | re.DOTALL)
    assert function is not None
    script = f"set -euo pipefail\n{function.group(0)}\nunix_tests {package}/*_test.go\n"
    result = subprocess.run(["bash", "-c", script], cwd=ROOT, capture_output=True, text=True, timeout=60, check=True)
    pattern = result.stdout.strip()
    assert pattern.startswith("^(") and pattern.endswith(")$"), pattern
    return set(pattern[2:-2].split("|"))


def _tests_in(path: Path) -> set[str]:
    return set(re.findall(r"^func (Test\w+)\(t \*testing\.T\)", path.read_text(encoding="utf-8"), re.MULTILINE))


def _unix_test_file(path: Path) -> bool:
    if path.name.endswith(("_windows_test.go", "_linux_test.go")):
        return False
    if path.name.endswith(("_darwin_test.go", "_unix_test.go")) or path.name.startswith("hook_foreign_guard"):
        return True
    build = next((line for line in path.read_text(encoding="utf-8").splitlines() if line.startswith("//go:build ")), "")
    return re.search(r"darwin|unix|!windows|!linux", build) is not None


def test_macos_lifecycle_leg_runs_the_darwin_packages_from_the_checkout() -> None:
    step = _macos_darwin_step()
    assert step["if"] == "runner.os == 'macOS'"
    assert "continue-on-error" not in step and "working-directory" not in step
    run = step["run"]
    # The runner's TMPDIR is under /var -> /private/var, and the Claude Code
    # settings reader refuses a file under a linked parent: the step points
    # TMPDIR at a link-free folder before the first go test.
    tmpdir = run.index('TMPDIR="$(cd "$RUNNER_TEMP/go-tmp" && pwd -P)"')
    assert run.index("export TMPDIR") > tmpdir
    assert run.index("go test") > run.index("export TMPDIR")
    assert "go test -count=1 -timeout 20m ./internal/agentprocess/... ./internal/gateway/connector/...\n" in run
    assert "for pkg in internal/gateway internal/cli; do\n" in run
    assert 'go test -count=1 -timeout 20m -run "$pattern" "./$pkg"\n' in run


@pytest.mark.skipif(os.name == "nt", reason="bash step")
@pytest.mark.parametrize(
    ("package", "darwin_tests"),
    [
        (
            "internal/gateway",
            {
                "TestFreshIdentityDarwinACLValidationAcceptsCleanDirectoryAndFile",
                "TestManagedHookPeerHomeResolvesTheCallersHome",
                "TestBindManagedHookSocket",
                "TestStandaloneHookSocketServesWhileTheAPIPortIsHeld",
            },
        ),
        (
            "internal/cli",
            {
                "TestStandaloneHookRuntimeUsesDescriptor",
                "TestEnterpriseHookWorkerOptionsCarryManagedHookSocket",
                "TestForeignHookGuardDenyAllowMatrix",
                "TestUnixEnterpriseCommandTree",
            },
        ),
    ],
)
def test_macos_lifecycle_leg_selects_the_unix_and_darwin_tests(package: str, darwin_tests: set[str]) -> None:
    selected = _selected_tests(package)
    assert darwin_tests <= selected
    files = sorted((ROOT / package).glob("*_test.go"))
    unix = set().union(*(_tests_in(path) for path in files if _unix_test_file(path)))
    other = set().union(*(_tests_in(path) for path in files if not _unix_test_file(path))) - unix
    assert selected == unix
    assert other and not selected & other
