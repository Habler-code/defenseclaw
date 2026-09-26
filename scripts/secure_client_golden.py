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
  * individual PowerShell functions and script-level constants in the Windows
    lifecycle module and installer that define the Secure Client layout,
    services, ACLs, and rendered policy. The module also hosts code for other
    profiles, so only these definitions are pinned there.

Usage:
  python3 scripts/secure_client_golden.py            # check (exit 1 on drift)
  python3 scripts/secure_client_golden.py --update   # regenerate deliberately
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
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
    "internal/ipc/authposture_gagate.go",
    "internal/winpath/managed_ipc_windows.go",
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
    ),
    "packaging/windows/install-enterprise.ps1": (
        "Assert-DefenseClawBootstrapUnsignedCertificationScope",
        "Assert-DefenseClawBootstrapLifecycleScope",
        "ConvertTo-DefenseClawConnectorList",
        "Get-DefenseClawRenderedEnterpriseConfig",
        "Get-DefenseClawRenderedEnterpriseTargets",
        "Resolve-DefenseClawConnectorMetadataVersion",
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
    ),
    "packaging/windows/install-enterprise.ps1": (
        "$script:DefenseClawSupportedConnectors",
        "$script:DefenseClawWindowsManagedEnterpriseSupportedConnectors",
    ),
}


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


def powershell_assignment_text(source: str, variable: str) -> str:
    lines = source.replace("\r\n", "\n").split("\n")
    matches = [line for line in lines if line.startswith(variable + " =")]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one assignment of {variable}, found {len(matches)}")
    return matches[0] + "\n"


def compute_tripwire(root: Path = ROOT) -> dict[str, dict[str, str]]:
    files: dict[str, str] = {}
    for pattern in PINNED_FILE_GLOBS:
        matched = sorted(path for path in root.glob(pattern) if path.is_file())
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
    actual = compute_tripwire()
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
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
