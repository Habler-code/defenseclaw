# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

import hashlib
import json
import os
import plistlib
import stat
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


SYSTEMD = ROOT / "packaging" / "systemd"
STANDALONE_ENV = {
    "Environment=DEFENSECLAW_DEPLOYMENT_MODE=managed_enterprise",
    "Environment=DEFENSECLAW_ENTERPRISE_PROFILE=standalone",
    "Environment=DEFENSECLAW_CONFIG=/etc/defenseclaw/config.yaml",
    "Environment=DEFENSECLAW_HOME=/var/lib/defenseclaw",
    "Environment=DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR=/var/lib/defenseclaw-hook-guardian",
}


def _unit(name: str) -> list[str]:
    return (SYSTEMD / name).read_text(encoding="utf-8").splitlines()


def test_systemd_standalone_unit_set_is_exact():
    units = sorted(p.name for p in SYSTEMD.iterdir() if p.suffix in {".service", ".socket", ".path", ".timer"})
    assert units == [
        "defenseclaw-enterprise-apply.path",
        "defenseclaw-enterprise-apply.service",
        "defenseclaw-enterprise-verify.service",
        "defenseclaw-enterprise-verify.timer",
        "defenseclaw-gateway-api.socket",
        "defenseclaw-gateway-hook.socket",
        "defenseclaw-gateway.service",
        "defenseclaw-hook-enumerator.service",
        "defenseclaw-hook-guardian-reconcile.service",
        "defenseclaw-hook-guardian.service",
        "defenseclaw-sensor-helper.service",
    ]
    # The racing reconcile timer, the ledger-less template unit and the
    # static sensor-helper environment file are gone.
    for retired in ("defenseclaw-hook-guardian.timer", "defenseclaw-hook-guardian@.service", "sensor-helper.env.example"):
        assert not (SYSTEMD / retired).exists()


def test_systemd_gateway_unit_pins_the_hardening_contract():
    lines = _unit("defenseclaw-gateway.service")
    required = STANDALONE_ENV | {
        "Type=notify",
        "NotifyAccess=main",
        "Sockets=defenseclaw-gateway-api.socket defenseclaw-gateway-hook.socket",
        "User=defenseclaw",
        "Group=defenseclaw",
        "Restart=always",
        "StartLimitIntervalSec=0",
        "WatchdogSec=60s",
        "PrivateUsers=no",
        "NoNewPrivileges=true",
        "ProtectSystem=strict",
        "ProtectHome=true",
        "ProtectProc=invisible",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
        "SystemCallFilter=@system-service",
        "MemoryDenyWriteExecute=true",
        "ReadWritePaths=/var/lib/defenseclaw /var/log/defenseclaw /run/defenseclaw -/run/defenseclaw-hook",
    }
    missing = sorted(line for line in required if line not in lines)
    assert not missing
    assert "DynamicUser=yes" not in lines


def test_systemd_sockets_hold_the_listeners_across_restarts():
    api = _unit("defenseclaw-gateway-api.socket")
    hook = _unit("defenseclaw-gateway-hook.socket")
    assert "ListenStream=127.0.0.1:18970" in api and "FileDescriptorName=api" in api
    for line in (
        "ListenStream=/run/defenseclaw-hook/hook.sock",
        "FileDescriptorName=hook",
        "SocketUser=defenseclaw",
        "SocketMode=0666",
        "DirectoryMode=0755",
    ):
        assert line in hook
    # A stop of the gateway must not take the listeners with it.
    assert not any(line.startswith("PartOf=") for line in api + hook)


def test_systemd_guardian_units_share_the_bounded_privilege_contract():
    for name in ("defenseclaw-hook-guardian.service", "defenseclaw-hook-guardian-reconcile.service"):
        lines = _unit(name)
        missing = sorted(line for line in STANDALONE_ENV | {
            "User=root",
            "NoNewPrivileges=true",
            "ProtectSystem=strict",
            "ReadOnlyPaths=/etc/defenseclaw /opt/defenseclaw",
            "CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_KILL CAP_SETGID CAP_SETUID",
            "UMask=0077",
        } if line not in lines)
        assert not missing, name
        assert "NoNewPrivileges=false" not in lines
    watch = _unit("defenseclaw-hook-guardian.service")
    assert any("enterprise hooks watch --manifest /etc/defenseclaw/hook-guardian/targets.yaml --interval 1m" in line for line in watch)
    assert "Restart=always" in watch
    assert any("enterprise hooks reconcile" in line for line in _unit("defenseclaw-hook-guardian-reconcile.service"))
    enumerator = _unit("defenseclaw-hook-enumerator.service")
    assert any("enterprise hooks enumerate --manifest /etc/defenseclaw/hook-guardian/targets.yaml --interval 5m" in line for line in enumerator)
    assert "ProtectHome=read-only" in enumerator
    assert "ReadWritePaths=/etc/defenseclaw/hook-guardian" in enumerator


def test_systemd_sensor_helper_owns_its_socket_directory():
    lines = _unit("defenseclaw-sensor-helper.service")
    assert "RuntimeDirectory=defenseclaw-sensor" in lines
    assert "ReadWritePaths=/run" not in lines
    assert not any(line.startswith("EnvironmentFile=") for line in lines)
    assert any("--service-account defenseclaw --home-dirs-from-manifest /etc/defenseclaw/hook-guardian/targets.yaml" in line for line in lines)
    assert any(line.startswith("SystemCallFilter=@system-service") for line in lines)
    assert "Before=defenseclaw-gateway.service" in lines


def test_systemd_apply_path_and_verify_timer():
    path = _unit("defenseclaw-enterprise-apply.path")
    for line in (
        "PathChanged=/etc/defenseclaw/config.yaml",
        "PathChanged=/etc/defenseclaw/secrets",
        "Unit=defenseclaw-enterprise-apply.service",
    ):
        assert line in path
    assert any("enterprise linux ensure --reason path --lock-wait 10m --json" in line for line in _unit("defenseclaw-enterprise-apply.service"))
    assert "OnCalendar=daily" in _unit("defenseclaw-enterprise-verify.timer")
    assert any("enterprise linux verify --json" in line for line in _unit("defenseclaw-enterprise-verify.service"))


def test_systemd_sysusers_and_tmpfiles():
    assert (SYSTEMD / "defenseclaw.sysusers").read_text(encoding="utf-8").splitlines()[-1].startswith("u defenseclaw -")
    tmpfiles = (SYSTEMD / "defenseclaw.conf").read_text(encoding="utf-8")
    assert "d /etc/defenseclaw 0755 root root -" in tmpfiles
    assert "d /etc/defenseclaw/hook-guardian 0750 root defenseclaw -" in tmpfiles
    assert "d /var/lib/defenseclaw-hook-guardian 0750 root defenseclaw -" in tmpfiles
    assert "d /var/lib/defenseclaw-enterprise 0700 root root -" in tmpfiles
    assert "d /run/defenseclaw-hook 0755 defenseclaw defenseclaw -" in tmpfiles
    assert "/etc/defenseclaw/secrets" not in tmpfiles
    sample = (SYSTEMD / "hook-guardian-targets.example.yaml").read_text(encoding="utf-8")
    assert "version: 1" in sample


def test_launchd_standalone_daemons():
    directory = ROOT / "packaging" / "launchd-standalone"
    labels = sorted(p.stem for p in directory.glob("*.plist"))
    assert labels == [
        "com.cisco.defenseclaw.apply",
        "com.cisco.defenseclaw.gateway",
        "com.cisco.defenseclaw.hook-enumerator",
        "com.cisco.defenseclaw.hook-guardian",
        "com.cisco.defenseclaw.sensor-helper",
        "com.cisco.defenseclaw.verify",
    ]
    for label in labels:
        with (directory / f"{label}.plist").open("rb") as fh:
            payload = plistlib.load(fh)
        assert payload["Label"] == label
        assert payload["ProgramArguments"][0].startswith("/opt/cisco/defenseclaw/bin/")
        assert "secureclient" not in json.dumps(payload).lower()
    with (directory / "com.cisco.defenseclaw.gateway.plist").open("rb") as fh:
        gateway = plistlib.load(fh)
    assert gateway["UserName"] == "_defenseclaw" and gateway["GroupName"] == "_defenseclaw"
    env = gateway["EnvironmentVariables"]
    assert env["DEFENSECLAW_ENTERPRISE_PROFILE"] == "standalone"
    assert env["DEFENSECLAW_DEPLOYMENT_MODE"] == "managed_enterprise"
    assert env["DEFENSECLAW_UNIX_SERVICE_ACCOUNT"] == "_defenseclaw"
    assert env["DEFENSECLAW_CONFIG"] == "/opt/cisco/defenseclaw/etc/config.yaml"
    for root_job in ("com.cisco.defenseclaw.hook-guardian", "com.cisco.defenseclaw.hook-enumerator", "com.cisco.defenseclaw.sensor-helper"):
        with (directory / f"{root_job}.plist").open("rb") as fh:
            assert "UserName" not in plistlib.load(fh)


def test_launchd_gateway_plist_uses_managed_paths():
    # DefenseClaw installs under /opt/cisco/secureclient/defenseclaw/.
    # The plist name and every path inside it follows that layout, and
    # the daemon runs as root (no UserName/GroupName keys — the managed
    # cloud auth provider requires root for its credential store).
    root = Path(__file__).resolve().parents[2]
    plist_path = root / "packaging" / "launchd" / "com.cisco.secureclient.defenseclaw.plist"

    with plist_path.open("rb") as fh:
        payload = plistlib.load(fh)

    assert payload["Label"] == "com.cisco.secureclient.defenseclaw"
    assert payload["ProgramArguments"] == ["/opt/cisco/secureclient/defenseclaw/bin/defenseclaw-gateway"]
    assert "UserName" not in payload, "daemon runs as root; UserName must be absent"
    assert "GroupName" not in payload, "daemon runs as root; GroupName must be absent"
    assert payload["WorkingDirectory"] == "/opt/cisco/secureclient/defenseclaw"
    assert payload["EnvironmentVariables"]["DEFENSECLAW_HOME"] == "/opt/cisco/secureclient/defenseclaw"
    assert (
        payload["EnvironmentVariables"]["DEFENSECLAW_CONFIG"]
        == "/opt/cisco/secureclient/defenseclaw/etc/config.yaml"
    )
    assert payload["EnvironmentVariables"]["DEFENSECLAW_DEPLOYMENT_MODE"] == "managed_enterprise"
    assert (
        payload["EnvironmentVariables"]["DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR"]
        == "/opt/cisco/secureclient/defenseclaw/hook-guardian-state"
    )
    assert payload["RunAtLoad"] is True
    assert payload["KeepAlive"] is True
    assert payload["Umask"] == 0o77
    assert payload["StandardOutPath"] == "/Library/Logs/Cisco/SecureClient/DefenseClaw/gateway.log"
    assert payload["StandardErrorPath"] == "/Library/Logs/Cisco/SecureClient/DefenseClaw/gateway.err.log"


def test_launchd_hook_guardian_is_separate_privileged_job():
    root = Path(__file__).resolve().parents[2]
    plist_path = root / "packaging" / "launchd" / "com.cisco.secureclient.defenseclaw.hook-guardian.plist"

    with plist_path.open("rb") as fh:
        payload = plistlib.load(fh)

    assert payload["Label"] == "com.cisco.secureclient.defenseclaw.hook-guardian"
    assert "UserName" not in payload
    # Guardian runs the long-running `enterprise hooks watch` command, not
    # the one-shot `reconcile` — fsnotify-driven auto-heal (~1 s) with a
    # 60 s periodic backstop, restart-managed via KeepAlive rather than
    # StartInterval. See internal/cli/enterprise_hooks.go runEnterpriseHooksWatch
    # for the loop's design (settle window + Stat-based rename-tail detection).
    assert payload["ProgramArguments"][1:4] == ["enterprise", "hooks", "watch"]
    # --interval 60s is the periodic backstop for tamper vectors the fsnotify
    # path intentionally cannot catch (SharedWriter Write/Chmod on native
    # agent configs, shared-across-connector generic scripts). Any drift in
    # this value should be a deliberate policy change, not an accidental edit.
    args = payload["ProgramArguments"]
    assert "--interval" in args, "guardian must pass --interval flag"
    interval_idx = args.index("--interval")
    # The value must immediately follow the flag, otherwise the CLI
    # will misparse the argv (a lone "60s" later in the vector would
    # bind to a different flag or be ignored).
    assert interval_idx + 1 < len(args), "--interval has no value argument"
    assert args[interval_idx + 1] == "60s", (
        f"guardian --interval value must be 60s, got {args[interval_idx + 1]!r}"
    )
    assert payload["EnvironmentVariables"]["DEFENSECLAW_DEPLOYMENT_MODE"] == "managed_enterprise"
    assert (
        payload["EnvironmentVariables"]["DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR"]
        == "/opt/cisco/secureclient/defenseclaw/hook-guardian-state"
    )
    # Long-running watch mode is kept alive by KeepAlive, NOT StartInterval.
    # StartInterval would pointlessly relaunch the process every N seconds
    # (and possibly spawn duplicates); KeepAlive relaunches only on exit.
    assert "StartInterval" not in payload
    assert payload.get("KeepAlive") is True


def test_release_archives_ship_enterprise_packaging_assets():
    config = yaml.safe_load((ROOT / ".goreleaser.yaml").read_text(encoding="utf-8"))
    for archive in config["archives"]:
        archive_files = archive["files"]
        assert "packaging/**/*" in archive_files
        assert "LICENSE*" in archive_files
        assert "NOTICE" in archive_files
        assert "THIRD_PARTY_LICENSES.txt" in archive_files
        assert "README*" in archive_files


def test_linux_enterprise_package_ships_every_unit_and_calls_the_lifecycle():
    config = yaml.safe_load((ROOT / ".goreleaser.yaml").read_text(encoding="utf-8"))
    (package,) = config["nfpms"]
    assert package["package_name"] == "defenseclaw-enterprise"
    assert package["formats"] == ["deb", "rpm"]
    assert package["bindir"] == "/opt/defenseclaw/bin"
    assert package["dependencies"] == ["systemd (>= 239)"]
    assert package["overrides"]["rpm"]["dependencies"] == ["systemd >= 239"]
    contents = {entry["src"]: entry["dst"] for entry in package["contents"]}
    for unit in SYSTEMD.iterdir():
        if unit.suffix in {".service", ".socket", ".path", ".timer"}:
            assert contents[f"packaging/systemd/{unit.name}"] == f"/usr/lib/systemd/system/{unit.name}"
    assert contents["packaging/systemd/defenseclaw.sysusers"] == "/usr/lib/sysusers.d/defenseclaw.conf"
    assert contents["packaging/systemd/defenseclaw.conf"] == "/usr/lib/tmpfiles.d/defenseclaw.conf"
    assert package["scripts"] == {
        "postinstall": "packaging/linux/postinstall.sh",
        "preremove": "packaging/linux/preremove.sh",
        "postremove": "packaging/linux/postremove.sh",
    }

    postinstall = (ROOT / "packaging/linux/postinstall.sh").read_text(encoding="utf-8")
    assert "enterprise linux ensure --from-package --reason package --json" in postinstall
    preremove = (ROOT / "packaging/linux/preremove.sh").read_text(encoding="utf-8")
    assert "enterprise linux uninstall --json" in preremove
    for name in ("postinstall.sh", "preremove.sh", "postremove.sh"):
        script = ROOT / "packaging/linux" / name
        assert script.stat().st_mode & 0o111, name
        text = script.read_text(encoding="utf-8")
        # A maintainer script never fails the package transaction.
        assert "set -e" not in text, name
        assert text.rstrip().endswith("exit 0"), name


@pytest.mark.skipif(os.name == "nt", reason="POSIX shell contract")
@pytest.mark.parametrize("argument", ["upgrade", "1", "deconfigure", "failed-upgrade"])
def test_linux_enterprise_preremove_leaves_upgrades_to_the_new_postinstall(tmp_path: Path, argument: str):
    # The script must exit before it touches the lifecycle on an upgrade;
    # a stub gateway on PATH would never be reached (it uses an absolute path).
    completed = subprocess.run(
        ["sh", str(ROOT / "packaging/linux/preremove.sh"), argument],
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0
    assert completed.stdout == completed.stderr == ""


def test_macos_enterprise_pkg_builder_calls_the_lifecycle():
    builder = (ROOT / "scripts/build-macos-enterprise-pkg.sh").read_text(encoding="utf-8")
    assert builder.startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in builder
    assert "enterprise macos ensure --from-package $downgrade --reason package --json" in builder
    # Downgrades stop in preinstall, before older binaries land, unless the
    # administrator placed the root-owned rollback marker.
    assert "refusing to downgrade" in builder and "allow-downgrade" in builder
    assert 'readonly INSTALL_BIN="opt/cisco/defenseclaw/bin"' in builder
    assert 'readonly PKG_ID="com.cisco.defenseclaw.enterprise"' in builder
    assert "com.cisco.secureclient.defenseclaw" in builder
    assert "GOARCH=arm64" in builder
    # Unsigned unless the release supplies Developer ID identities.
    assert 'if [ -n "${MACOS_INSTALLER_SIGN_IDENTITY:-}" ]' in builder
    assert 'if [ -n "${MACOS_APP_SIGN_IDENTITY:-}" ]' in builder
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "packaging-linux-enterprise:" in makefile
    assert "packaging-macos-enterprise:" in makefile


def test_third_party_license_text_and_platform_packaging_contracts():
    third_party = (ROOT / "THIRD_PARTY_LICENSES.txt").read_text(encoding="utf-8")
    section_separator = "=" * 78
    heading, first_section, _ = third_party.partition(f"{section_separator}\n")
    assert first_section
    assert "not an exhaustive inventory" in " ".join(heading.split())

    def exact_section(title: str) -> str:
        marker = f"{section_separator}\n{title}\n{section_separator}\n\n"
        assert third_party.count(marker) == 1
        remainder = third_party.partition(marker)[2]
        body, next_section, _ = remainder.partition(f"\n{section_separator}\n")
        return body if next_section else remainder

    section_digests = {
        "mvdan.cc/sh/v3 v3.13.1 (BSD-3-Clause)": (
            "ce63850f77649f00d1394045e2794ffb09a5596beabac51c9548edd958845d7c"
        ),
        "github.com/google/cel-go v0.30.0 (LICENSE)": (
            "4cdb9af102dfbb0ca03d87d6f650a505df098646a4080f4665b389ad9c6caa02"
        ),
        "github.com/antlr4-go/antlr/v4 v4.13.1 (LICENSE)": (
            "683fcd416d83b64781e229a3c2a598462fbf55c5c9fea54be244766b22c033cf"
        ),
        "golang.org/x/exp v0.0.0-20250305212735-054e65f0b394 (LICENSE)": (
            "911f8f5782931320f5b8d1160a76365b83aea6447ee6c04fa6d5591467db9dad"
        ),
        "golang.org/x/exp v0.0.0-20250305212735-054e65f0b394 (PATENTS)": (
            "96f408bfae65bf137fc2525d3ecb030271c50c1e90799f87abf8846d8dd505cc"
        ),
    }
    for title, digest in section_digests.items():
        assert digest in heading
        assert hashlib.sha256(exact_section(title).encode()).hexdigest() == digest

    provenance_urls = (
        "https://github.com/mvdan/sh/blob/v3.13.1/LICENSE",
        "https://github.com/google/cel-go/blob/v0.30.0/LICENSE",
        "https://github.com/antlr4-go/antlr/blob/v4.13.1/LICENSE",
        "https://github.com/golang/exp/blob/"
        "054e65f0b394d1bf387a254295588fb7e5bd0516/LICENSE",
        "https://github.com/golang/exp/blob/"
        "054e65f0b394d1bf387a254295588fb7e5bd0516/PATENTS",
    )
    for provenance_url in provenance_urls:
        assert provenance_url in heading
    assert "cel.dev/expr v0.25.1 is Apache-2.0-only" in heading

    go_mod = (ROOT / "go.mod").read_text(encoding="utf-8")
    go_sum = (ROOT / "go.sum").read_text(encoding="utf-8")
    go_mod_requirements = (
        "\tgithub.com/google/cel-go v0.30.0\n",
        "\tmvdan.cc/sh/v3 v3.13.1\n",
        "\tcel.dev/expr v0.25.1 // indirect\n",
        "\tgithub.com/antlr4-go/antlr/v4 v4.13.1 // indirect\n",
        "\tgolang.org/x/exp v0.0.0-20250305212735-054e65f0b394 // indirect\n",
    )
    for requirement in go_mod_requirements:
        assert requirement in go_mod

    go_module_sums = (
        "cel.dev/expr v0.25.1 h1:1KrZg61W6TWSxuNZ37Xy49ps13NUovb66QLprthtwi4=",
        "github.com/antlr4-go/antlr/v4 v4.13.1 "
        "h1:SqQKkuVZ+zWkMMNkjy5FZe5mr5WURWnlpmOuzYWrPrQ=",
        "github.com/google/cel-go v0.30.0 "
        "h1:ll54AkzKunWkBn9wSoiUXbFZXYZTkdJGNXTBXUoolGo=",
        "golang.org/x/exp v0.0.0-20250305212735-054e65f0b394 "
        "h1:nDVHiLt8aIbd/VzvPWN6kSOPE7+F/fNFDSXLVYkE/Iw=",
        "mvdan.cc/sh/v3 v3.13.1 "
        "h1:DP3TfgZhDkT7lerUdnp6PTGKyxxzz6T+cOlY/xEvfWk=",
    )
    for module_sum in go_module_sums:
        assert f"{module_sum}\n" in go_sum

    notice = (ROOT / "NOTICE").read_text(encoding="utf-8")
    notice_words = " ".join(notice.split())
    assert "GoReleaser archive Syft SBOM sidecars" in notice
    assert "Windows Setup merged SPDX 2.3 SBOM" in notice
    assert "not an exhaustive dependency inventory" in notice_words
    notice_dependencies = (
        "CEL-Go (github.com/google/cel-go) — Apache-2.0 with BSD-3-Clause component",
        "CEL expression protobufs (cel.dev/expr) — Apache-2.0",
        "ANTLR4 Go runtime (github.com/antlr4-go/antlr/v4) — BSD-3-Clause",
        "Go experimental packages (golang.org/x/exp) — BSD-3-Clause",
    )
    for dependency in notice_dependencies:
        assert dependency in notice
    manifest_paths = (
        "extensions/defenseclaw/package.json",
        "extensions/defenseclaw/openclaw.plugin.json",
        "extensions/defenseclaw/package-lock.json",
        "docs-site/package.json",
        "docs-site/package-lock.json",
    )
    for manifest_path in manifest_paths:
        assert (ROOT / manifest_path).is_file()
        assert manifest_path in notice
        assert manifest_path in heading
    assert "the runtime archive carries them as root package.json" in notice_words
    assert "is not placed in that runtime archive" in notice_words
    assert "not a DefenseClaw runtime artifact" in notice_words

    manifest = (ROOT / "MANIFEST.in").read_text(encoding="utf-8").splitlines()
    for name in ("LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt"):
        assert f"include {name}" in manifest

    bundle_builder = (ROOT / "scripts/build-macos-bundle.sh").read_text(encoding="utf-8")
    windows_builder = (ROOT / "scripts/windows-native-ci.ps1").read_text(encoding="utf-8-sig")
    windows_installer = (ROOT / "scripts/build-windows-installer.ps1").read_text(
        encoding="utf-8-sig"
    )
    windows_gateway_license_staging = """\
    foreach ($file in @('LICENSE', 'NOTICE', 'THIRD_PARTY_LICENSES.txt')) {
        foreach ($targetRoot in @($gatewayVerificationStage, $stage)) {
            Copy-Item -LiteralPath (Join-Path $WorkspaceRoot $file) -Destination $targetRoot -Force
        }
    }"""
    for name in ("LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt"):
        assert f'cp {name} ' in bundle_builder
    assert windows_gateway_license_staging in windows_builder
    assert (
        "foreach ($file in @('pyproject.toml', 'README.md', 'LICENSE', 'NOTICE', "
        "'THIRD_PARTY_LICENSES.txt', 'MANIFEST.in'))"
    ) in windows_builder
    assert (
        "Copy-Item -LiteralPath (Join-Path $WorkspaceRoot $file) "
        "-Destination $packageStage -Force"
    ) in windows_builder
    assert (
        """\
        '--source', $stage,
        '--output', $gatewayArchive,"""
        in windows_builder
    )
    assert (
        """\
        '--source', $gatewayVerificationStage,
        '--output', $gatewayArchiveVerification,"""
        in windows_builder
    )
    assert "gateway ZIP must contain exactly one root $file file" in windows_builder
    assert "gateway ZIP $file differs from the canonical source file" in windows_builder
    assert "Expand-Archive -LiteralPath $gatewayZip -DestinationPath $gatewayPayloadDir" in (
        windows_installer
    )
    assert "Write-ZipFromDirectory $gatewayPayloadDir $embeddedGatewayZip" in windows_installer


@pytest.mark.skipif(os.name == "nt", reason="launchd installer POSIX ownership and executable-bit contract")
def test_launchd_enterprise_installer_enforces_managed_config_trust_boundary():
    installer = ROOT / "packaging" / "launchd" / "install-enterprise.sh"

    assert installer.is_file()
    assert installer.stat().st_mode & stat.S_IXUSR
    subprocess.run(["bash", "-n", str(installer)], check=True)
    help_result = subprocess.run(
        [str(installer), "--help"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert "--config" in help_result.stdout
    assert "root:wheel" in help_result.stdout
    assert "0640" in help_result.stdout
    assert "No dedicated service user or group" in help_result.stdout

    text = installer.read_text(encoding="utf-8")
    required = {
        'CONFIG_DEST="/opt/cisco/secureclient/defenseclaw/etc/config.yaml"',
        'install_file_atomic "$CONFIG_SOURCE" "$CONFIG_DEST" root wheel 0640',
        'install_file_atomic "$MANIFEST_SOURCE" "$MANIFEST_DEST" root wheel 0640',
        'create_directory_no_replace "$BINARY_ROOT" root wheel 0755',
        'create_directory_no_replace "$BIN_DIR" root wheel 0755',
        'create_directory_no_replace "$ETC_DIR" root wheel 0755',
        'create_directory_no_replace "$RUNTIME_DIR" root wheel 0750',
        'create_directory_no_replace "$GUARDIAN_DIR" root wheel 0750',
        'create_directory_no_replace "$AUTH_DIR" root wheel 0750',
        'create_directory_no_replace "$LOG_DIR" root wheel 0750',
        'for parent in /opt /opt/cisco /opt/cisco/secureclient "$LOG_VENDOR_DIR" "$LOG_PRODUCT_DIR"; do',
        'assert_path_metadata "$CONFIG_DEST" file 0 "$WHEEL_GID" 640',
        'assert_path_metadata "$MANIFEST_DEST" file 0 "$WHEEL_GID" 640',
        'assert_path_metadata "$ETC_DIR" dir 0 "$WHEEL_GID" 755',
        'assert_path_metadata "$RUNTIME_DIR" dir 0 "$WHEEL_GID" 750',
        'assert_path_metadata "$GUARDIAN_DIR" dir 0 "$WHEEL_GID" 750',
        'assert_path_metadata "$AUTH_DIR" dir 0 "$WHEEL_GID" 750',
        'assert_path_metadata "$LOG_DIR" dir 0 "$WHEEL_GID" 750',
        'assert_existing_secure_dir_or_absent "$RUNTIME_DIR"',
        'assert_existing_secure_dir_or_absent "$LOG_DIR"',
        'assert_existing_secure_dir_or_absent "$LOG_VENDOR_DIR"',
        'assert_existing_secure_dir_or_absent "$LOG_PRODUCT_DIR"',
        "assert_trusted_system_dir /opt",
        "assert_trusted_system_dir /opt/cisco",
        "assert_trusted_system_dir /opt/cisco/secureclient",
        'refuse_symlink "$CONFIG_DEST"',
        "assert_no_write_acl()",
        'assert_no_write_acl "$path"',
        "write-capable macOS ACL is not trusted",
        'EnvironmentVariables',
        'DEFENSECLAW_DEPLOYMENT_MODE',
    }
    missing = sorted(value for value in required if value not in text)
    assert not missing
    directory_creation = 'create_directory_no_replace "$BINARY_ROOT" root wheel 0755'
    for ancestor in ("/opt", "/opt/cisco", "/opt/cisco/secureclient"):
        assert text.index(directory_creation) < text.index(f"assert_trusted_system_dir {ancestor}")
    stale_service_identity_contract = {
        "SERVICE_USER",
        "SERVICE_GROUP",
        "SERVICE_UID",
        "SERVICE_GID",
        "assert_existing_acl_safe_dir_or_absent",
    }
    present = sorted(value for value in stale_service_identity_contract if value in text)
    assert not present

    # Idempotent-reinstall contract: the installer no longer refuses on
    # existing markers. It logs a reconcile message, unloads any current-
    # generation launchd labels, and relocates legacy paths under LOG_DIR.
    # Per-user ~/.defenseclaw is informational only — the hook-guardian
    # daemon owns per-user reconciliation, so the installer must not
    # abort or delete on those markers.
    assert "reconciling existing DefenseClaw installation in place" in text
    assert "idempotent reinstall" in text
    assert "fresh managed_enterprise install" in text
    assert "will be reconciled by hook-guardian" in text
    assert "moved legacy path aside" in text
    # Old refusal strings must NOT be present — they were the exact
    # symptoms the reinstall rework fixes.
    assert "no changes were made. This installer is fresh-install-only" not in text
    assert "remain on the current version" not in text
    assert '/usr/bin/dscl . -list /Users' in text
    assert '/usr/bin/dscl . -read "/Users/${local_user}" NFSHomeDirectory' in text
    assert '"${local_home}/.defenseclaw"' in text
    assert '"${local_home}/.local/bin/defenseclaw"' in text
    assert '"${local_home}/.local/bin/defenseclaw-gateway"' in text
    assert "BINARY_ROOT=/opt/cisco/secureclient/defenseclaw" in text
    assert "LOG_DIR=/Library/Logs/Cisco/SecureClient/DefenseClaw" in text
    assert "LEGACY_GATEWAY_PLIST_DEST=/Library/LaunchDaemons/com.defenseclaw.gateway.plist" in text
    assert "LEGACY_GUARDIAN_PLIST_DEST=/Library/LaunchDaemons/com.defenseclaw.hook-guardian.plist" in text
    assert "com.defenseclaw.gateway" in text
    assert "com.defenseclaw.hook-guardian" in text
    # Reconcile happens before any mutation: bootout / rebootstrap the
    # current-gen labels and relocate legacy paths before the ROLLBACK
    # snapshot arms so an interrupted reinstall rolls back cleanly.
    reconcile_offset = text.index("reconciling existing DefenseClaw installation in place")
    assert reconcile_offset < text.index('ROLLBACK_DIR="$(/usr/bin/mktemp -d')
    assert reconcile_offset < text.index('assert_trusted_file_source "$CONFIG_SOURCE"')
    # Pre-mutation logs-chain trust check MUST run before the early
    # mkdir/mv relocation block. Without this a symlinked /Library/Logs
    # ancestor or an ACL-writable LOG_DIR ancestor could let the
    # `mkdir -p` + `mv` steps below relocate legacy config / audit
    # material into an attacker-controlled target before the later
    # validation (line ~582) has a chance to fire. Mirrors the
    # `_assert_trusted_logs_chain_or_die` gate in packaging/macos/install.sh.
    logs_chain_gate = text.index("Ancestor trust check: before ANY mkdir/chown/chmod on the")
    early_mkdir_landing = text.index("Ensure LOG_DIR exists early so the legacy relocation below")
    legacy_relocation = text.index("moved legacy path aside")
    assert logs_chain_gate < early_mkdir_landing
    assert logs_chain_gate < legacy_relocation
    # The gate must call the primitive assertions against every
    # /Library/Logs/... ancestor, not just LOG_DIR itself.
    gate_block = text[logs_chain_gate:early_mkdir_landing]
    assert 'assert_trusted_system_dir /Library' in gate_block
    assert 'assert_existing_secure_dir_or_absent /Library/Logs' in gate_block
    assert 'assert_existing_secure_dir_or_absent "$LOG_VENDOR_DIR"' in gate_block
    assert 'assert_existing_secure_dir_or_absent "$LOG_PRODUCT_DIR"' in gate_block
    assert 'assert_existing_secure_dir_or_absent "$LOG_DIR"' in gate_block
    # install_file_atomic uses mv -f (rename(2), atomic replace) so an
    # existing regular destination is overwritten cleanly on reinstall.
    # ln (hardlink) would fail with EEXIST on the second run.
    atomic_install = text[
        text.index("install_file_atomic() {") : text.index("plist_pins_managed_mode() {")
    ]
    assert '/bin/mv -f -- "$temporary" "$destination"' in atomic_install
    assert '/bin/ln -- "$temporary" "$destination"' not in atomic_install
    assert '/bin/launchctl enable "system/${GATEWAY_LABEL}"' in text
    assert '/bin/launchctl kickstart -k "system/${GATEWAY_LABEL}"' in text
    # Legacy launchd labels are unloaded (via bootout) so their stale
    # plists don't keep spawn-and-crashing; the current-gen labels are
    # ALSO booted out before rebootstrap during a reinstall.
    assert '/bin/launchctl bootout "system/${_legacy_label}"' in text

    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "macos-enterprise-packaging:" in workflow
    assert "./scripts/test-macos-enterprise-packaging.sh" in workflow

    smoke = (ROOT / "scripts" / "test-macos-enterprise-packaging.sh").read_text(encoding="utf-8")
    # Smoke test asserts the reinstall contract end-to-end.
    assert "managed_root=\"/opt/cisco/secureclient/defenseclaw\"" in smoke
    assert "config_dest=\"${managed_root}/etc/config.yaml\"" in smoke
    assert "log_dir=/Library/Logs/Cisco/SecureClient/DefenseClaw" in smoke
    assert "assert_no_defenseclaw_identity()" in smoke
    assert 'legacy_managed_root="/Library/Application Support/DefenseClaw"' in smoke
    assert "legacy_binary_root=/Library/DefenseClaw" in smoke
    # Reinstall-contract-specific expectations:
    assert "Reinstall reconciles machine-wide state" in smoke
    assert "idempotent reinstall failed" in smoke
    assert "reinstall did not restore config to freshly-rendered content" in smoke
    assert "reinstall did not emit legacy-relocation log line" in smoke
    assert "reconciling existing DefenseClaw installation in place" in smoke
    # Untrusted config source is still refused (trust contract unchanged
    # by the reinstall rework):
    assert "installer accepted writable config source (source-trust contract broken)" in smoke
    assert "untrusted source refusal did not identify managed config trust" in smoke
    assert 'trusted_fixture="/Library/DefenseClawPackagingSmoke.$$"' in smoke


def test_launchd_enterprise_installer_matches_cisco_plist_layout():
    installer = ROOT / "packaging" / "launchd" / "install-enterprise.sh"
    text = installer.read_text(encoding="utf-8")

    gateway_plist = ROOT / "packaging" / "launchd" / "com.cisco.secureclient.defenseclaw.plist"
    guardian_plist = (
        ROOT / "packaging" / "launchd" / "com.cisco.secureclient.defenseclaw.hook-guardian.plist"
    )
    with gateway_plist.open("rb") as fh:
        gateway = plistlib.load(fh)
    with guardian_plist.open("rb") as fh:
        guardian = plistlib.load(fh)

    home = gateway["EnvironmentVariables"]["DEFENSECLAW_HOME"]
    config = gateway["EnvironmentVariables"]["DEFENSECLAW_CONFIG"]
    auth_dir = gateway["EnvironmentVariables"]["DEFENSECLAW_HOOK_GUARDIAN_AUTH_DIR"]
    # The manifest path follows the --manifest flag; explicit lookup instead
    # of positional indexing (ProgramArguments[-1] used to be the manifest
    # under `hooks reconcile --manifest <path>`, but the current watch-mode
    # args add `--interval 60s` after the manifest, making index -1 wrong).
    guardian_args = guardian["ProgramArguments"]
    manifest_flag = guardian_args.index("--manifest")
    manifest = guardian_args[manifest_flag + 1]

    assert f"BINARY_ROOT={home}" in text
    assert f'CONFIG_DEST="{config}"' in text
    assert f'MANIFEST_DEST="{manifest}"' in text
    assert f'AUTH_DIR="{auth_dir}"' in text
    assert f'GATEWAY_LABEL={gateway["Label"]}' in text
    assert f'GUARDIAN_LABEL={guardian["Label"]}' in text
    assert '"system/${GATEWAY_LABEL}"' in text
    assert '"system/${GUARDIAN_LABEL}"' in text
    assert "snapshot_file()" in text
    assert "restore_snapshots()" in text
    assert "rebootstrap_previously_loaded_job()" in text
    assert "rollback_install()" in text
    assert "GATEWAY_WAS_LOADED=true" in text
    assert "GUARDIAN_WAS_LOADED=true" in text
    assert 'snapshot_file "$destination"' in text
    assert text.index("ROLLBACK_ARMED=true") < text.index('stop_job_if_loaded "$GUARDIAN_LABEL"')
    assert 'stop_job_if_loaded "$GATEWAY_LABEL"' in text
    assert 'stop_job_if_loaded "$GUARDIAN_LABEL"' in text
    assert "ROLLBACK_ARMED=false" in text
    assert "system/com.defenseclaw." not in text

    deployment_docs = (
        ROOT / "docs-site" / "content" / "docs" / "setup" / "enterprise-deployment.mdx"
    ).read_text(encoding="utf-8")
    documented_contract = {
        "There is no dedicated `defenseclaw` service user on macOS.",
        "| `/opt/cisco/secureclient/defenseclaw/etc` | `root:wheel` | `0755` |",
        "| `/opt/cisco/secureclient/defenseclaw/etc/config.yaml` | `root:wheel` | `0640` |",
        "| `/opt/cisco/secureclient/defenseclaw/runtime` | `root:wheel` | `0750` |",
        "| `/opt/cisco/secureclient/defenseclaw/hook-guardian` | `root:wheel` | `0750` |",
        "| `/opt/cisco/secureclient/defenseclaw/hook-guardian/targets.yaml` | `root:wheel` | `0640` |",
        "| `/opt/cisco/secureclient/defenseclaw/hook-guardian-state` | `root:wheel` | `0750` |",
        "| `/Library/Logs/Cisco/SecureClient/DefenseClaw` | `root:wheel` | `0750` |",
        "A failure after jobs are stopped restores the previous binary, config, manifest, and plists",
    }
    missing_contract = sorted(value for value in documented_contract if value not in deployment_docs)
    assert not missing_contract
