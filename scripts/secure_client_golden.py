#!/usr/bin/env python3
# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""Secure Client source tripwire.

Production Secure Client (release branch release-defenseclaw-enterprise-26.8.4)
ships the Windows and macOS managed_enterprise lifecycle from these sources. The
behavioral goldens under testdata/secure_client_golden prove what that lifecycle
produces; this tripwire additionally fails when any Secure Client-owned source
changes, so every such change is a deliberate, reviewed regeneration rather than
a side effect.

Pinned items:
  * whole files that exist only for the Secure Client distribution (macOS and
    launchd packaging, the AVC build kit, CMID/cloudreg/broker code, the Secure
    Client IPC contract);
  * the managed local IPC surface the Secure Client gateway and sensor helper
    bind (internal/ipc server, listener, ACL, peer-auth and path code);
  * the host gate that keeps the hook-time foreign-hook guard a no-op on
    Secure Client hosts (internal/cli/hook_foreign_guard_host*.go);
  * individual PowerShell functions and script-level constants in the Windows
    lifecycle module and installer that define the Secure Client layout,
    services, ACLs, and rendered policy, every profile helper those
    functions call for their Secure Client branch (profile gates, per-profile
    roots, broker and dependency selection, version floors, the cross-profile
    conflict checks), and the installer's parameter block. The module also
    hosts code for other profiles, so only these definitions are pinned there.

Usage:
  python3 scripts/secure_client_golden.py            # check (exit 1 on drift)
  python3 scripts/secure_client_golden.py --update   # regenerate deliberately
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
GOLDEN = ROOT / "testdata" / "secure_client_golden" / "source_tripwire.json"

PINNED_FILE_GLOBS: tuple[str, ...] = (
    "packaging/launchd/*.plist",
    "packaging/launchd/install-enterprise.sh",
    "packaging/macos/install.sh",
    "packaging/macos/uninstall.sh",
    "packaging/macos/lib/*.sh",
    "packaging/macos/lib/*.py",
    "packaging/scripts/*.sh",
    "packaging/scripts/lib/*",
    "cmd/defenseclaw-cmid-broker/*.go",
    "internal/managed/cmidbroker/*.go",
    "internal/managed/cloudreg/*.go",
    "internal/managed/cmid_library*.go",
    "internal/ipc/peerauth_darwin.go",
    "internal/ipc/peerauth_unix.go",
    "internal/ipc/peerauth_windows.go",
    "internal/ipc/authposture_gagate.go",
    "internal/ipc/server*.go",
    "internal/ipc/listen*.go",
    "internal/ipc/acl_windows.go",
    "internal/ipc/paths*.go",
    "internal/winpath/managed_ipc_windows.go",
    # The gate that keeps the hook-time foreign-hook guard a no-op on hosts
    # without an administrator-written standalone summary directory or the
    # administrator-only standalone registration.
    "internal/cli/hook_foreign_guard_host*.go",
    "proto/defenseclaw/secureclient/v1/*.proto",
)

PINNED_POWERSHELL_FUNCTIONS: dict[str, tuple[str, ...]] = {
    "packaging/windows/DefenseClawEnterprise.psm1": (
        "Get-DefenseClawLayout",
        "Get-DefenseClawEnumeratorServiceName",
        "Get-DefenseClawCMIDBrokerServiceName",
        "Get-DefenseClawCMIDBrokerImage",
        "Get-DefenseClawSensorHelperServiceName",
        "Get-DefenseClawSensorHelperImage",
        "Get-DefenseClawManagedServiceNames",
        "Assert-DefenseClawUnsignedCertificationScope",
        "New-DefenseClawCanonicalPathAcl",
        "Set-DefenseClawPathAcl",
        "Get-DefenseClawServiceEnvironmentValues",
        "Set-DefenseClawServiceEnvironment",
        "Get-DefenseClawSensorHelperEnvironmentValues",
        "Set-DefenseClawSensorHelperServiceEnvironment",
        "Set-DefenseClawCMIDBrokerAuthKey",
        "Get-DefenseClawFailureActionsBytes",
        "Set-DefenseClawExactFailureActions",
        "Set-DefenseClawServiceRegistryAcl",
        "Assert-DefenseClawServiceRegistryAcl",
        "Set-DefenseClawManagedServices",
        "Initialize-DefenseClawManagedIPCDirectory",
        "Set-DefenseClawManagedAcls",
        "Assert-DefenseClawServiceConfiguration",
        "Assert-DefenseClawManagedServiceConfigurations",
        "New-DefenseClawRequiredRights",
        # Profile helpers the pinned functions call for their Secure Client
        # branch, and the cross-profile checks the Secure Client lifecycle runs.
        "Get-DefenseClawTrustedMachineRoots",
        "Set-DefenseClawEnterpriseProfile",
        "Get-DefenseClawEnterpriseProfile",
        "Test-DefenseClawStandaloneProfile",
        "Get-DefenseClawProfileRoots",
        "Resolve-DefenseClawProfileFromLifecycleDirectory",
        "Test-DefenseClawBrokerEnabled",
        "Test-DefenseClawLayoutBrokerEnabled",
        "Get-DefenseClawGatewayServiceDependencies",
        "Get-DefenseClawClaudeMinimumClientVersion",
        "Get-DefenseClawAgentApplicationControlAttestationSchemaVersion",
        "Test-DefenseClawProfileDeploymentInstalled",
        "Test-DefenseClawProfileDeploymentRecordTrusted",
        "Assert-DefenseClawNoOtherProfileDeployment",
        "Assert-DefenseClawOtherProfileLifecycleIdle",
    ),
    "packaging/windows/install-enterprise.ps1": (
        "Assert-DefenseClawBootstrapUnsignedCertificationScope",
        "Assert-DefenseClawBootstrapLifecycleScope",
        "ConvertTo-DefenseClawConnectorList",
        "Get-DefenseClawRenderedEnterpriseConfig",
        "Get-DefenseClawRenderedEnterpriseTargets",
        "Resolve-DefenseClawConnectorMetadataVersion",
        # Bootstrap helpers on the Secure Client path: machine and profile
        # roots, module trust, the native session/SID helper, and the
        # interactive-user selection the rendered targets depend on.
        "Get-DefenseClawTrustedMachineRoots",
        "Get-DefenseClawBootstrapProfileRoots",
        "Initialize-DefenseClawBootstrapNativePath",
        "Assert-DefenseClawBootstrapModuleTrust",
        "Test-DefenseClawBootstrapInteractiveUserSID",
        "Select-DefenseClawActiveInteractiveUserProfiles",
        "Get-DefenseClawEligibleInteractiveUserProfiles",
    ),
}

PINNED_POWERSHELL_ASSIGNMENTS: dict[str, tuple[str, ...]] = {
    "packaging/windows/DefenseClawEnterprise.psm1": (
        "$script:SystemSID",
        "$script:OwnerRightsSID",
        "$script:AdministratorsSID",
        "$script:UsersSID",
        "$script:AuthenticatedUsersSID",
        "$script:TrustedInstallerSID",
        "$script:ServiceSDDL",
        "$script:ServiceDescription",
        "$script:ServiceFailureRestartQuiescenceSeconds",
        "$script:SchemaVersion",
        "$script:AgentApplicationControlAttestationSchemaVersion",
        "$script:AgentApplicationControlPrerequisite",
        "$script:DefenseClawEnterpriseProfile",
        "$script:DefenseClawPinnedPayloadSHA256",
        "$script:DefenseClawAllowedSignerSHA256",
        "$script:DefenseClawTrustMode",
    ),
    "packaging/windows/install-enterprise.ps1": (
        "$script:DefenseClawSupportedConnectors",
        "$script:DefenseClawWindowsManagedEnterpriseSupportedConnectors",
    ),
}


# Scripts whose top-level param() block is pinned: the installer's parameter
# set and defaults (including -EnterpriseProfile SecureClient) are the Secure
# Client installer's command line.
PINNED_POWERSHELL_SCRIPT_PARAMS: tuple[str, ...] = ("packaging/windows/install-enterprise.ps1",)


def _normalized(data: bytes) -> bytes:
    """Hash checkout-independent bytes: Windows checkouts may use CRLF."""
    return data.replace(b"\r\n", b"\n")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(_normalized(data)).hexdigest()


def powershell_function_text(source: str, name: str) -> str:
    """Return one top-level PowerShell function definition.

    The Secure Client module and installer define every function at column 0
    and close it with a lone ``}`` at column 0, which this extractor relies on
    (and fails loudly if that convention is ever broken for a pinned name).
    """

    lines = source.replace("\r\n", "\n").split("\n")
    header = re.compile(r"^function\s+" + re.escape(name) + r"\s*\{\s*$")
    starts = [index for index, line in enumerate(lines) if header.match(line)]
    if len(starts) != 1:
        raise ValueError(f"expected exactly one top-level definition of {name}, found {len(starts)}")
    start = starts[0]
    for end in range(start + 1, len(lines)):
        if lines[end] == "}":
            return "\n".join(lines[start : end + 1]) + "\n"
        if lines[end].startswith("function "):
            break
    raise ValueError(f"could not find the column-0 closing brace for {name}")


def powershell_script_param_text(source: str) -> str:
    """Return a script's top-level param() block (``param(`` to ``)`` at column 0)."""

    lines = source.replace("\r\n", "\n").split("\n")
    starts = [index for index, line in enumerate(lines) if line == "param("]
    if len(starts) != 1:
        raise ValueError(f"expected exactly one top-level param( block, found {len(starts)}")
    start = starts[0]
    for end in range(start + 1, len(lines)):
        if lines[end] == ")":
            return "\n".join(lines[start : end + 1]) + "\n"
    raise ValueError("could not find the column-0 closing parenthesis of the param( block")


def powershell_assignment_text(source: str, variable: str) -> str:
    lines = source.replace("\r\n", "\n").split("\n")
    matches = [line for line in lines if line.startswith(variable + " =")]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one assignment of {variable}, found {len(matches)}")
    return matches[0] + "\n"


def tracked_files(root: Path) -> set[str] | None:
    """Return the paths git tracks under root, or None when root is not a checkout.

    Only tracked sources ship, so untracked and ignored files a checkout
    accumulates (Finder's .DS_Store, editor backups) are never pinned.
    """

    try:
        toplevel = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            capture_output=True,
            check=True,
            timeout=60,
        )
        if Path(toplevel.stdout.decode("utf-8").strip()).resolve() != root.resolve():
            return None
        listed = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            capture_output=True,
            check=True,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError, UnicodeDecodeError):
        return None
    return {entry.decode("utf-8") for entry in listed.stdout.split(b"\0") if entry}


def pinned_file_matches(root: Path, pattern: str, tracked: set[str] | None) -> list[Path]:
    """Return the files one pinned glob selects.

    In a git checkout only tracked files count. Without git (for example a
    `git archive` export) dot-files are skipped instead, since no pinned
    source is one.
    """

    matched: list[Path] = []
    for path in sorted(root.glob(pattern)):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        if tracked is None:
            if any(part.startswith(".") for part in relative.parts):
                continue
        elif relative.as_posix() not in tracked:
            continue
        matched.append(path)
    return matched


def compute_tripwire(root: Path = ROOT) -> dict[str, dict[str, str]]:
    files: dict[str, str] = {}
    tracked = tracked_files(root)
    for pattern in PINNED_FILE_GLOBS:
        matched = pinned_file_matches(root, pattern, tracked)
        if not matched:
            raise ValueError(f"pinned Secure Client glob matched nothing: {pattern}")
        for path in matched:
            if path.name.endswith("_test.go"):
                continue
            files[path.relative_to(root).as_posix()] = _sha256(path.read_bytes())
    functions: dict[str, str] = {}
    for relative, names in PINNED_POWERSHELL_FUNCTIONS.items():
        source = (root / relative).read_text(encoding="utf-8-sig")
        for name in names:
            text = powershell_function_text(source, name)
            functions[f"{relative}#{name}"] = _sha256(text.encode("utf-8"))
    for relative, variables in PINNED_POWERSHELL_ASSIGNMENTS.items():
        source = (root / relative).read_text(encoding="utf-8-sig")
        for variable in variables:
            text = powershell_assignment_text(source, variable)
            functions[f"{relative}#{variable}"] = _sha256(text.encode("utf-8"))
    for relative in PINNED_POWERSHELL_SCRIPT_PARAMS:
        source = (root / relative).read_text(encoding="utf-8-sig")
        functions[f"{relative}#param"] = _sha256(powershell_script_param_text(source).encode("utf-8"))
    return {"files": dict(sorted(files.items())), "powershell": dict(sorted(functions.items()))}


def drift(expected: dict[str, dict[str, str]], actual: dict[str, dict[str, str]]) -> list[str]:
    messages: list[str] = []
    for section in ("files", "powershell"):
        want = expected.get(section, {})
        got = actual.get(section, {})
        for key in sorted(set(want) | set(got)):
            if key not in got:
                messages.append(f"{section}: {key} is pinned but no longer present")
            elif key not in want:
                messages.append(f"{section}: {key} is new and not yet pinned")
            elif want[key] != got[key]:
                messages.append(f"{section}: {key} changed")
    return messages


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--update", action="store_true", help="regenerate the tripwire after a reviewed change")
    args = parser.parse_args(argv)
    try:
        actual = compute_tripwire()
    except ValueError as err:
        # A pinned definition the extractor can no longer find (renamed,
        # removed, or reformatted away from the column-0 convention) is drift,
        # not a crash: report it the same way, and never pin around it.
        if args.update:
            print(f"secure-client-golden: cannot update: {err}", file=sys.stderr)
            return 1
        _report_drift([str(err)])
        return 1
    if args.update:
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(json.dumps(actual, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"secure-client-golden: updated {GOLDEN.relative_to(ROOT)}")
        return 0
    expected = json.loads(GOLDEN.read_text(encoding="utf-8"))
    problems = drift(expected, actual)
    if not problems:
        print("secure-client-golden: source tripwire OK")
        return 0
    _report_drift(problems)
    return 1


def _report_drift(problems: list[str]) -> None:
    print("Secure Client source tripwire drift:", file=sys.stderr)
    for problem in problems:
        print(f"  - {problem}", file=sys.stderr)
    print(
        "Production Secure Client behavior must not change. If this change is intended, "
        "review it (and the behavioral goldens), then run "
        "`python3 scripts/secure_client_golden.py --update` "
        "(testdata/secure_client_golden/README.md).",
        file=sys.stderr,
    )


if __name__ == "__main__":
    raise SystemExit(main())
