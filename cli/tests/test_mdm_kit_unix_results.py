# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""What the Unix package scriptlets and MDM wrappers report and exit with.

The deb/rpm maintainer scripts, the macOS pkg postinstall and the MDM
wrappers run the standalone lifecycle and turn its result into the package
transaction's outcome or the MDM's result document. These checks run the
shipped scripts against stub tools (systemctl, the package managers and the
gateway binary) in a temporary directory; nothing on the host is touched.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LINUX = ROOT / "packaging" / "linux"
APPLY_PATH = "defenseclaw-enterprise-apply.path"

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX shell scripts")


def _write_stub(bin_dir: Path, name: str, body: str) -> None:
    stub = bin_dir / name
    stub.write_text("#!/bin/sh\n" + body + "\n", encoding="utf-8")
    stub.chmod(0o755)


def _rooted(text: str, replacements: dict[str, str]) -> str:
    for old, new in replacements.items():
        assert old in text, old
        text = text.replace(old, new)
    return text


class _Host:
    """A temporary host: stub tools on PATH, a stub gateway and a call log."""

    def __init__(self, tmp_path: Path, gateway_rc: int = 0, apply_path_active: bool = False):
        self.tmp = tmp_path
        self.bin = tmp_path / "bin"
        self.bin.mkdir()
        self.log = tmp_path / "calls.log"
        self.gateway = tmp_path / "defenseclaw-gateway"
        self.state = tmp_path / "state"
        self.run_systemd = tmp_path / "run-systemd-system"
        self.run_systemd.mkdir()
        self.active = tmp_path / "apply-path-active"
        if apply_path_active:
            self.active.write_text("", encoding="utf-8")
        _write_stub(self.bin, "systemctl", f"""echo "systemctl $*" >>'{self.log}'
case "$1" in
    is-active) [ -e '{self.active}' ] ;;
    stop) rm -f '{self.active}' ;;
    start) : >'{self.active}' ;;
esac""")
        for tool in ("systemd-sysusers", "systemd-tmpfiles"):
            _write_stub(self.bin, tool, f"""echo "{tool} $*" >>'{self.log}'""")
        _write_stub(self.tmp, "defenseclaw-gateway", f"""echo "gateway $*" >>'{self.log}'
echo '{{"schema_version":2,"ok":true}}'
exit {gateway_rc}""")

    def run(self, script: str, *args: str) -> subprocess.CompletedProcess[str]:
        path = self.tmp / "script.sh"
        path.write_text(script, encoding="utf-8")
        env = {"PATH": f"{self.bin}:/usr/bin:/bin"}
        return subprocess.run(["sh", str(path), *args], env=env, capture_output=True, text=True, timeout=60)

    def calls(self) -> list[str]:
        return self.log.read_text(encoding="utf-8").splitlines() if self.log.exists() else []


def _linux_scriptlet(host: _Host, name: str) -> str:
    return _rooted(
        (LINUX / name).read_text(encoding="utf-8"),
        {
            "gateway=/opt/defenseclaw/bin/defenseclaw-gateway": f"gateway={host.gateway}",
            "state=/var/lib/defenseclaw-enterprise": f"state={host.state}",
            "/run/systemd/system": str(host.run_systemd),
        },
    )


# RHEL-F12: the postinstall's own systemd-tmpfiles and daemon-reload started
# the config-apply path unit, whose ensure won the lifecycle lock and did the
# upgrade, while the scriptlet's ensure (default 5 s wait) exited 75 and every
# upgrade reported "the lifecycle reported a problem".
def test_linux_postinstall_holds_the_apply_trigger_and_waits_for_the_lock(tmp_path: Path) -> None:
    host = _Host(tmp_path, gateway_rc=0, apply_path_active=True)
    result = host.run(_linux_scriptlet(host, "postinstall.sh"), "configure")
    assert result.returncode == 0, result.stderr
    assert "the managed deployment is active" in result.stdout
    calls = host.calls()
    ensure = next(i for i, call in enumerate(calls) if call.startswith("gateway "))
    assert calls[ensure] == "gateway enterprise linux ensure --from-package --reason package --json --lock-wait 10m"
    stop = calls.index(f"systemctl stop {APPLY_PATH}")
    for tool in ("systemd-sysusers", "systemd-tmpfiles", "systemctl daemon-reload"):
        index = next(i for i, call in enumerate(calls) if call.startswith(tool))
        assert stop < index < ensure, (tool, calls)
    assert calls.index(f"systemctl start {APPLY_PATH}") > ensure, calls


def test_linux_postinstall_leaves_an_inactive_apply_trigger_alone(tmp_path: Path) -> None:
    host = _Host(tmp_path, gateway_rc=0, apply_path_active=False)
    assert host.run(_linux_scriptlet(host, "postinstall.sh"), "1").returncode == 0
    calls = host.calls()
    assert f"systemctl stop {APPLY_PATH}" not in calls and f"systemctl start {APPLY_PATH}" not in calls, calls


@pytest.mark.parametrize(("rc", "message"), [(75, "held the lock for 10 minutes"), (1, "the lifecycle reported a problem")])
def test_linux_postinstall_reports_a_lifecycle_problem_and_restores_the_trigger(tmp_path: Path, rc: int, message: str) -> None:
    host = _Host(tmp_path, gateway_rc=rc, apply_path_active=True)
    result = host.run(_linux_scriptlet(host, "postinstall.sh"), "configure")
    assert result.returncode == 0  # a package install never fails on the lifecycle
    assert message in result.stderr
    assert host.calls()[-1] == f"systemctl start {APPLY_PATH}"


# unix-lifecycle-3: preremove ran uninstall with the 5 s default and exited 0
# on busy (75), so dpkg/rpm deleted the binaries and units while machine
# policy, per-user hooks and the running gateway still named them.
@pytest.mark.parametrize(("rc", "exit_code"), [(0, 0), (1, 0), (75, 1)])
def test_linux_preremove_waits_for_the_lock_and_refuses_the_removal_when_busy(tmp_path: Path, rc: int, exit_code: int) -> None:
    host = _Host(tmp_path, gateway_rc=rc)
    result = host.run(_linux_scriptlet(host, "preremove.sh"), "remove")
    assert result.returncode == exit_code, (result.stdout, result.stderr)
    assert host.calls() == ["gateway enterprise linux uninstall --json --lock-wait 10m"]
    if rc == 75:
        assert "nothing was removed" in result.stderr
    elif rc:
        assert "uninstall reported a problem" in result.stderr


# After preremove refuses a removal (busy lock), dpkg runs "postinst
# abort-remove": the postinstall must not wait on the same lock again.
def test_linux_postinstall_does_nothing_after_a_refused_removal(tmp_path: Path) -> None:
    host = _Host(tmp_path, gateway_rc=75, apply_path_active=True)
    result = host.run(_linux_scriptlet(host, "postinstall.sh"), "abort-remove")
    assert result.returncode == 0, result.stderr
    assert host.calls() == []


def _macos_pkg_postinstall(host: _Host) -> str:
    builder = (ROOT / "scripts" / "build-macos-enterprise-pkg.sh").read_text(encoding="utf-8")
    match = re.search(r"cat >\"\$SCRIPTS/postinstall\" <<'EOF'\n(.*?)\nEOF\n", builder, re.DOTALL)
    assert match, "the pkg postinstall heredoc was not found"
    return _rooted(
        match.group(1) + "\n",
        {
            "gateway=/opt/cisco/defenseclaw/bin/defenseclaw-gateway": f"gateway={host.gateway}",
            "state=/opt/cisco/defenseclaw/lifecycle": f"state={host.state}",
        },
    )


@pytest.mark.parametrize("rc", [0, 75])
def test_macos_pkg_postinstall_waits_for_the_lock(tmp_path: Path, rc: int) -> None:
    host = _Host(tmp_path, gateway_rc=rc)
    result = host.run(_macos_pkg_postinstall(host))
    assert result.returncode == rc
    assert host.calls() == ["gateway enterprise macos ensure --from-package --reason package --json --lock-wait 10m"]


MDM = ROOT / "packaging" / "mdm"
SCHEMA = MDM / "contract" / "lifecycle-result.schema.json"


def _shell_function(text: str, name: str) -> str:
    match = re.search(rf"^{re.escape(name)}\(\) \{{.*?^\}}$", text, re.MULTILINE | re.DOTALL)
    assert match, f"{name} not found"
    return match.group(0)


# Each stub answers the queries dc_install_package makes; DC_TEST_INSTALLED is
# the version already installed (empty: not installed).
_PACKAGE_STUBS = {
    "dpkg-deb": """case "$3" in Package) echo defenseclaw-enterprise ;; Version) echo "$DC_TEST_VERSION" ;; Architecture) echo amd64 ;; esac""",
    "dpkg": """case "$1" in --print-architecture) echo amd64 ;; esac""",
    "dpkg-query": """[ -n "$DC_TEST_INSTALLED" ] || exit 1
printf 'install ok installed %s' "$DC_TEST_INSTALLED\"""",
    "rpm": """case "$1" in
    -qp) case "$3" in *NAME*) echo defenseclaw-enterprise ;; *) echo "$DC_TEST_VERSION" ;; esac ;;
    -q)
        if [ -z "$DC_TEST_INSTALLED" ]; then echo "package defenseclaw-enterprise is not installed"; exit 1; fi
        [ "$2" != --qf ] || printf '%s' "$DC_TEST_INSTALLED"
        ;;
esac""",
    "pkgutil": """case "$1" in
    --expand) mkdir -p "$3" && printf '<pkg-ref id="com.cisco.defenseclaw.enterprise" version="%s" onConclusion="none">x.pkg</pkg-ref>\\n' "$DC_TEST_VERSION" >"$3/Distribution" ;;
    --pkg-info) [ -n "$DC_TEST_INSTALLED" ] || exit 1; echo "version: $DC_TEST_INSTALLED" ;;
    *) exit 1 ;;
esac""",
    "installer": ":",
}


def _noop_ensure_result(platform: str, version: str, warnings: bool) -> dict:
    # The field order and indentation of the Go lifecycle result encoder.
    document = {
        "schema_version": 2, "ok": True, "action": "ensure", "noop": True, "noop_reason": "up_to_date",
        "profile": "standalone", "platform": platform, "product_version": version, "installed_version": version,
        "installed": True, "transaction_pending": False,
        "services": [{"name": "com.cisco.defenseclaw.gateway", "kind": "gateway", "state": "running", "required": True}],
        "readiness": {"gateway": True, "guardian": True, "enumerator": True, "sensor_helper": True},
        "inspection": {"local": "unknown", "ai_defense": "unknown"}, "machine_policy": {},
        "enrollment": {"targets": 0, "pending": 0, "failed": 0, "exempt": 0},
        "coverage_complete": True, "security_complete": True, "errors": [],
    }
    if warnings:
        document["warnings"] = [{"code": "verify_failed", "message": 'a "quoted" \\ message'}]
    document["exit_code"] = 0
    return document


# MAC-F18: the wrapper's one result document reported the no-op ensure that
# followed the package step ("action": "ensure", "noop": true) after the
# package's postinstall had upgraded 0.8.11 to 0.8.12.
@pytest.mark.parametrize(
    ("source", "installed", "version", "action", "code", "text"),
    [
        ("defenseclaw-enterprise.pkg", "0.8.11", "0.8.12", "upgrade", "package_upgraded", "from 0.8.11 to 0.8.12"),
        ("defenseclaw-enterprise.pkg", "", "0.8.12", "install", "package_installed", "package 0.8.12"),
        ("defenseclaw-enterprise.deb", "1.4.0", "1.5.0", "upgrade", "package_upgraded", "from 1.4.0 to 1.5.0"),
        ("defenseclaw-enterprise.rpm", "1.4.0-1", "1.5.0-1", "upgrade", "package_upgraded", "from 1.4.0 to 1.5.0"),
        ("defenseclaw-enterprise.rpm", "", "1.5.0-1", "install", "package_installed", "package 1.5.0"),
        ("defenseclaw-enterprise.deb", "1.5.0", "1.5.0", None, None, None),
    ],
)
@pytest.mark.parametrize("warnings", [False, True])
def test_unix_wrapper_result_reports_the_package_step(
    tmp_path: Path, source: str, installed: str, version: str, action: str | None, code: str | None, text: str | None, warnings: bool
) -> None:
    import json

    os_dir = "macos" if source.endswith(".pkg") else "linux"
    wrapper = (MDM / os_dir / "defenseclaw-enterprise.sh").read_text(encoding="utf-8")
    functions = "\n".join(
        _shell_function(wrapper, name)
        for name in ("dc_json_escape", "dc_busy_output", "dc_require_product_version", "dc_package_release_version",
                     "dc_package_step", "dc_annotate_package_step", "dc_install_package")
    )
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, body in _PACKAGE_STUBS.items():
        _write_stub(bin_dir, name, body)
    platform = "darwin" if os_dir == "macos" else "linux"
    release = version.split("-")[0] if source.endswith(".rpm") else version
    result = tmp_path / "result.json"
    result.write_text(json.dumps(_noop_ensure_result(platform, release, warnings), indent=2) + "\n", encoding="utf-8")
    script = f"""
DC_SCRIPT_OS={platform}
DC_EXIT_FAILURE=1 DC_EXIT_INVALID=2 DC_EXIT_BUSY=75
DC_LINUX_PACKAGE=defenseclaw-enterprise DC_MACOS_PACKAGE_ID=com.cisco.defenseclaw.enterprise
DC_PRODUCT_VERSION='' DC_STAGE='{tmp_path}' DC_STAGED_SOURCE='{tmp_path / source}' DC_RESULT='{result}'
DC_PACKAGE_ACTION='' DC_PACKAGE_PREVIOUS='' DC_PACKAGE_VERSION=''
dc_fail_result() {{ echo "FAIL $2: $3"; exit "$1"; }}
dc_log() {{ :; }}
dc_extract_payload() {{ :; }}
{functions}
dc_install_package
dc_annotate_package_step
cat "$DC_RESULT"
"""
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "DC_TEST_VERSION": version, "DC_TEST_INSTALLED": installed}
    for shell in ("sh", "bash"):
        completed = subprocess.run([shell, "-c", script], env=env, capture_output=True, text=True, timeout=30)
        assert completed.returncode == 0, (shell, completed.stdout, completed.stderr)
        document = json.loads(completed.stdout)
        if action is None:
            assert document == _noop_ensure_result(platform, release, warnings), shell
            continue
        assert document["action"] == action and document["noop"] is False and "noop_reason" not in document, (shell, document)
        notes = [w for w in document.get("warnings", []) if w["code"] == code]
        assert len(notes) == 1 and text in notes[0]["message"], (shell, document.get("warnings"))
        if warnings:
            assert {"code": "verify_failed", "message": 'a "quoted" \\ message'} in document["warnings"]
        try:
            import jsonschema
        except ImportError:
            continue
        validator = jsonschema.Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))
        assert not sorted(validator.iter_errors(document), key=str), shell


def test_unix_wrapper_annotates_only_a_successful_ensure() -> None:
    for os_dir in ("linux", "macos"):
        main = _shell_function((MDM / os_dir / "defenseclaw-enterprise.sh").read_text(encoding="utf-8"), "dc_main")
        assert 'dc_run_lifecycle "$gateway" "$@" || status=$?\n    [ "$status" != 0 ] || dc_annotate_package_step\n' in main
