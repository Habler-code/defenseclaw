# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Windows enterprise payload signer pin.

A production enterprise lifecycle accepts a payload file only when its valid
Authenticode signature names the DefenseClaw publisher, or a certificate an
administrator listed by SHA-256 fingerprint. Before the pin, any valid signer
was accepted.
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
INSTALLER = ROOT / "packaging" / "windows" / "install-enterprise.ps1"
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"
SMOKE = ROOT / "packaging" / "windows" / "tests" / "enterprise-payload-signer-smoke.ps1"
LIFECYCLE_CLI = ROOT / "internal" / "cli" / "windows_enterprise_service.go"


def read(path: Path) -> str:
    assert path.is_file(), f"required Windows enterprise artifact is missing: {path}"
    return path.read_text(encoding="utf-8")


def function_body(source: str, name: str) -> str:
    start = source.index(f"function {name} {{")
    end = source.find("\nfunction ", start + 1)
    return source[start : end if end != -1 else len(source)]


def test_every_authenticode_source_check_pins_the_publisher() -> None:
    module = read(MODULE)
    assert "$script:DefenseClawPayloadPublisher = 'Cisco Systems, Inc.'" in module

    signer = function_body(module, "Assert-DefenseClawPayloadSigner")
    assert "X509NameType]::SimpleName" in signer
    assert "[StringComparison]::Ordinal" in signer
    assert "Get-DefenseClawCertificateSha256" in signer
    assert "-ccontains $fingerprint" in signer
    assert "not the DefenseClaw publisher" in signer

    regular = function_body(module, "Assert-DefenseClawRegularSource")
    # The publisher check runs for every production Authenticode source and is
    # skipped only by the certification-only -AllowUnsigned relaxation.
    assert "if (-not $AllowUnsigned) {" in regular
    assert regular.index("SignatureStatus]::Valid") < regular.index(
        "Assert-DefenseClawPayloadSigner"
    )

    descriptor = function_body(module, "Get-DefenseClawSourceDescriptor")
    assert "trusted_signer_sha256 = $trustedSigners" in descriptor
    assert "-AdditionalTrustedSignerSha256 $trustedSigners" in descriptor

    current = function_body(module, "Assert-DefenseClawSourceDescriptorCurrent")
    assert "Get-DefenseClawSourceTrustedSigners -Source $Source" in current

    install = function_body(module, "Install-DefenseClawSourceDescriptor")
    assert "Get-DefenseClawSourceTrustedSigners -Source $Source" in install

    sources = function_body(module, "Get-DefenseClawLifecycleSources")
    assert sources.count("-AdditionalTrustedSignerSha256 $AdditionalTrustedSignerSha256") == 2

    lifecycle = function_body(module, "Invoke-DefenseClawEnterpriseLifecycle")
    assert "[string[]]$AdditionalTrustedSignerSha256" in lifecycle
    assert "cannot be combined with -AllowUnsigned" in lifecycle
    assert lifecycle.index("ConvertTo-DefenseClawTrustedSignerSet") < lifecycle.index(
        "Assert-DefenseClawAdministrator"
    )
    assert "-AdditionalTrustedSignerSha256 $trustedSigners" in lifecycle


def test_fingerprint_parameter_accepts_only_sha256() -> None:
    for source, name in (
        (read(MODULE), "ConvertTo-DefenseClawTrustedSignerSet"),
        (read(INSTALLER), "ConvertTo-DefenseClawBootstrapTrustedSignerSet"),
    ):
        body = function_body(source, name)
        assert "'^[0-9A-Fa-f]{64}\\z'" in body
        assert "'^[0-9A-Fa-f]{40}\\z'" in body
        assert "SHA-1" in body
        assert "ToLowerInvariant()" in body


def test_installer_pins_module_signer_before_import() -> None:
    installer = read(INSTALLER)
    assert "[string[]]$AdditionalTrustedSignerSha256," in installer

    trust = function_body(installer, "Assert-DefenseClawBootstrapModuleTrust")
    assert trust.index("SignatureStatus]::Valid") < trust.index(
        "Assert-DefenseClawBootstrapModuleSigner"
    )
    bootstrap_signer = function_body(installer, "Assert-DefenseClawBootstrapModuleSigner")
    assert "'Cisco Systems, Inc.'" in bootstrap_signer
    assert "[StringComparison]::Ordinal" in bootstrap_signer

    main = installer[installer.index("$bootstrapEnvironment = $null") :]
    assert "cannot be combined with -AllowUnsigned" in main
    assert main.index("ConvertTo-DefenseClawBootstrapTrustedSignerSet") < main.index(
        "Assert-DefenseClawBootstrapModuleTrust"
    )
    assert main.index("-AdditionalTrustedSignerSha256 $trustedSigners") < main.index(
        "Import-Module"
    )
    assert "AdditionalTrustedSignerSha256 = $trustedSigners" in main


def test_endpoint_signer_pin_matches_the_assembly_publisher_contract() -> None:
    """Every endpoint pin must accept exactly what Setup assembly accepts.

    The Setup EXE carries no additional trusted signer, so if the publisher
    enforced when the managed payload is assembled differs from the endpoint
    pin, a cleanly assembled Setup fails every endpoint lifecycle action.
    """
    literal = r"'([^']+)'"
    assembly_ps = read(ROOT / "packaging" / "scripts" / "lib" / "assert-cisco-signature.ps1")
    assembly_sh = read(ROOT / "packaging" / "scripts" / "lib" / "assert-cisco-signature.sh")
    broker = read(ROOT / "internal" / "managed" / "cmidbroker" / "library_trust.go")
    publishers = {
        "assembly (pwsh)": re.search(
            r"^\$script:DefenseClawCiscoPublisherCN = " + literal, assembly_ps, re.MULTILINE
        ),
        "assembly (bash)": re.search(
            r"^readonly _DEFENSECLAW_CISCO_PUBLISHER_CN=" + literal, assembly_sh, re.MULTILINE
        ),
        "lifecycle module": re.search(
            r"^\$script:DefenseClawPayloadPublisher = " + literal, read(MODULE), re.MULTILINE
        ),
        "bootstrap installer": re.search(
            r"\[string\]::Equals\(\$publisher, " + literal,
            function_body(read(INSTALLER), "Assert-DefenseClawBootstrapModuleSigner"),
        ),
        "cmid broker": re.search(r'^const CMIDLibraryPublisher = "([^"]+)"', broker, re.MULTILINE),
    }
    missing = [name for name, match in publishers.items() if match is None]
    assert not missing, f"publisher literal not found for: {missing}"
    values = {name: match.group(1) for name, match in publishers.items()}
    assert set(values.values()) == {"Cisco Systems, Inc."}, values

    # Both sides compare the same certificate name form, and assembly checks
    # every Authenticode payload file before it is embedded.
    assert "X509NameType]::SimpleName" in assembly_ps
    assert "Assert-CiscoSignature -Path (Join-Path $PayloadDir $name)" in read(
        ROOT / "packaging" / "scripts" / "lib" / "assemble.ps1"
    )
    assert 'defenseclaw_assert_cisco_signature "${PAYLOAD_DIR}/${name}"' in read(
        ROOT / "packaging" / "scripts" / "lib" / "assemble.sh"
    )


def test_cli_forwards_additional_signers_as_one_file_argument() -> None:
    cli = read(LIFECYCLE_CLI)
    assert '"additional-trusted-signer-sha256"' in cli
    assert (
        'args = append(args, "-AdditionalTrustedSignerSha256", '
        'strings.Join(opts.additionalTrustedSignerSHA256, ","))'
    ) in cli


def windows_powershell_engines() -> list[str]:
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    candidates = [
        system_root / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe",
        Path(os.environ.get("ProgramW6432", r"C:\Program Files")) / "PowerShell" / "7" / "pwsh.exe",
    ]
    engines: list[str] = []
    for candidate in candidates:
        if candidate.is_file() and str(candidate) not in engines:
            engines.append(str(candidate))
    if not engines:
        fallback = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
        if fallback:
            engines.append(fallback)
    return engines


@pytest.mark.skipif(os.name != "nt", reason="requires native Windows PowerShell")
@pytest.mark.parametrize(
    "engine",
    windows_powershell_engines() or (None,),
    ids=lambda engine: Path(engine).stem if engine else "missing",
)
def test_payload_signer_smoke_runs_on_every_engine(engine: str | None) -> None:
    assert engine, "Windows CI must provide Windows PowerShell 5.1 or PowerShell 7"
    completed = subprocess.run(
        [
            engine,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SMOKE),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8-sig",
        errors="replace",
        timeout=300,
        check=False,
    )
    assert completed.returncode == 0, (
        f"payload signer smoke failed\nstdout:\n{completed.stdout}\nstderr:\n{completed.stderr}"
    )
    report = json.loads(completed.stdout.strip().splitlines()[-1])
    for field in (
        "ok",
        "bootstrap_signer_pinned",
        "module_signer_pinned",
        "signer_fingerprint_validated",
        "lifecycle_parameter_validated",
    ):
        assert report[field] is True, field
    if report["foreign_signer_available"]:
        assert report["foreign_signer_rejected"] is True
        assert report["foreign_descriptor_recheck_pinned"] is True
