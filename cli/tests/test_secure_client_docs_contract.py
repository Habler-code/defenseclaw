# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Secure Client docs must match the code they describe.

Each check reads the fact from the implementation (bundle script,
PowerShell module, certification harness) where it can, so a later code
change that the docs do not follow fails here.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEPLOYMENT_DOC = ROOT / "docs-site/content/docs/setup/enterprise-deployment.mdx"
THREAT_MODEL = ROOT / "docs/WINDOWS-ENTERPRISE-THREAT-MODEL.md"
CERTIFICATION_DOC = ROOT / "docs/WINDOWS-ENTERPRISE-CERTIFICATION.md"
AVC_HANDOFF = ROOT / "docs/WINDOWS-AVC-PACKAGING-HANDOFF.md"
BUNDLE_SCRIPT = ROOT / "packaging/scripts/build-managed-windows-bundle.sh"
MODULE = ROOT / "packaging/windows/DefenseClawEnterprise.psm1"
HARNESS = ROOT / "scripts/test-windows-enterprise-hardening.ps1"

NUMBER_WORDS = {
    3: "three",
    4: "four",
    5: "five",
    6: "six",
    7: "seven",
    8: "eight",
    9: "nine",
}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _flat(text: str) -> str:
    return " ".join(text.split())


def _threat_row(row_id: str) -> str:
    rows = [
        line
        for line in _read(THREAT_MODEL).splitlines()
        if line.startswith(f"| {row_id} |")
    ]
    assert len(rows) == 1, (row_id, len(rows))
    return rows[0]


def _certification_row(name: str) -> str:
    rows = [
        line
        for line in _read(CERTIFICATION_DOC).splitlines()
        if line.startswith(f"| {name} |")
    ]
    assert len(rows) == 1, (name, len(rows))
    return rows[0]


def _powershell_function(text: str, name: str) -> str:
    start = text.index(f"function {name} {{")
    end = text.find("\nfunction ", start + 1)
    return text[start : end if end != -1 else len(text)]


def test_avc_handoff_payload_tree_lists_every_expected_payload_file() -> None:
    script = _read(BUNDLE_SCRIPT)
    block = re.search(r"^EXPECTED_PAYLOAD_NAMES=\(\n(.*?)^\)", script, re.MULTILINE | re.DOTALL)
    assert block, "EXPECTED_PAYLOAD_NAMES not found"
    expected = set(block.group(1).split())
    assert len(expected) >= 8

    doc = _read(AVC_HANDOFF)
    tree = re.search(r"├── payload/\n(.*?)\n├── ", doc, re.DOTALL)
    assert tree, "payload/ tree not found in the AVC handoff"
    documented = {
        line.split("── ", 1)[1].strip()
        for line in tree.group(1).splitlines()
        if "── " in line
    }
    assert documented == expected

    count = NUMBER_WORDS[len(expected)]
    flat = _flat(doc)
    assert f"The {count}-file inventory is closed" in flat
    assert f"signs all {count} files under `payload/`" in flat


def test_threat_model_service_rows_cover_every_managed_service() -> None:
    names = _powershell_function(_read(MODULE), "Get-DefenseClawManagedServiceNames")
    returned = re.search(r"return @\((.*?)\n    \)", names, re.DOTALL)
    assert returned, "Get-DefenseClawManagedServiceNames return list not found"
    service_count = len([line for line in returned.group(1).splitlines() if line.strip()])
    production = (
        "DefenseClawGateway",
        "DefenseClawCMIDBroker",
        "DefenseClawSensorHelper",
        "DefenseClawHookGuardian",
        "DefenseClawHookEnumerator",
    )
    assert service_count == len(production)
    count = NUMBER_WORDS[service_count]

    w01 = _threat_row("W-01")
    assert f"all {count} exact production services" in w01
    for name in production:
        assert f"`{name}`" in w01, name

    w36 = _threat_row("W-36")
    assert f"all {count} services disabled before stop" in w36
    assert f"readiness before all {count} become automatic" in w36
    assert "DefenseClawSensorHelper" in w36

    # W-20 and W-31 are certified for the four service processes the
    # harness probes, so they name them instead of giving a bare count.
    for row_id in ("W-20", "W-31"):
        assert "sensor-helper" in _threat_row(row_id), row_id

    rows = "\n".join(
        line for line in _read(THREAT_MODEL).splitlines() if line.startswith("| W-")
    )
    for stale in (
        "all four exact production services",
        "all four services",
        "all four service processes",
        "all four managed-service environments",
        "all four become automatic",
        "all four service registry",
    ):
        assert stale not in rows, stale


def test_certification_doc_matches_the_harness_upgrade_and_service_sets() -> None:
    harness = _read(HARNESS)
    upgrade_inputs = set(re.findall(r"^\s*\[string\]\$Upgrade(\w+)Binary = ''", harness, re.MULTILINE))
    assert upgrade_inputs == {"Broker", "Gateway", "ACP", "Hook", "SensorHelper", "CLI"}
    count = NUMBER_WORDS[len(upgrade_inputs)]
    assert f"requires all {count} upgrade binaries" in harness

    flat = _flat(_read(CERTIFICATION_DOC))
    assert f"required {count}-binary upgrade set" in flat
    assert f"all {count} staged upgrade hashes" in flat
    assert f"without all {count} second-build artifacts" in flat
    for stale in (
        "three-binary upgrade set",
        "all four staged upgrade hashes",
        "all four second-build artifacts",
        "three-service set",
        "those three services remained responsive",
    ):
        assert stale not in flat, stale

    # The harness token probe and recovery contract include the sensor
    # helper, so the matrix rows that describe them must too.
    recovery = _powershell_function(harness, "Get-CertificationFailureActionContract")
    assert "$script:SensorHelperServiceName" in recovery
    tokens = _powershell_function(harness, "Get-CertificationServiceTokenSnapshot")
    assert "$script:SensorHelperServiceName" in tokens
    for row in ("Actual service tokens", "Recovery semantics"):
        assert "sensor helper" in _certification_row(row), row
