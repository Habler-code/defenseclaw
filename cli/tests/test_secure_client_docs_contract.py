# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0

"""Secure Client docs must match the code they describe.

Each check reads the fact from the implementation (bundle script,
PowerShell module, certification harness) where it can, so a later code
change that the docs do not follow fails here.
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
DEPLOYMENT_DOC = ROOT / "docs-site/content/docs/setup/enterprise-deployment.mdx"
THREAT_MODEL = ROOT / "docs/WINDOWS-ENTERPRISE-THREAT-MODEL.md"
CERTIFICATION_DOC = ROOT / "docs/WINDOWS-ENTERPRISE-CERTIFICATION.md"
AVC_HANDOFF = ROOT / "docs/WINDOWS-AVC-PACKAGING-HANDOFF.md"
BUNDLE_SCRIPT = ROOT / "packaging/scripts/build-managed-windows-bundle.sh"
MODULE = ROOT / "packaging/windows/DefenseClawEnterprise.psm1"
HARNESS = ROOT / "scripts/test-windows-enterprise-hardening.ps1"
LIFECYCLE_CLI = ROOT / "internal/cli/windows_enterprise_service.go"
HOOK_RECONCILE = ROOT / "internal/cli/enterprise_hooks.go"
CODEX_INSTALL = ROOT / "internal/enterprisehooks/install_windows_codex_secure.go"
FOREIGN_HOOKS = ROOT / "internal/gateway/connector/hookexec/foreign_hooks.go"

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


def _go_function(text: str, name: str) -> str:
    start = text.index(f"func {name}(")
    end = text.find("\n}\n", start)
    assert end != -1, name
    return text[start:end]


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
    # The bundle script's own staging comment gives the same count.
    assert f"# ---- kit/payload: the {count} files AVC signs" in script


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


def test_activation_order_docs_match_the_module() -> None:
    # The transaction activation demand-starts each service explicitly; the
    # sensor helper is started right after the broker, not by the gateway's
    # SCM dependency.
    module = _read(MODULE)
    start = module.index("Start-DefenseClawService -Name $Layout.BrokerServiceName")
    block = module[start : module.index("-StartMode 2", start)]
    steps = {
        "$Layout.BrokerServiceName": "broker",
        "$Layout.SensorHelperServiceName": "sensor helper",
        "guardian": "guardian",
        "$GatewayServiceName": "gateway",
        "$enumeratorServiceName": "enumerator",
    }
    order = [
        steps[match.group(1) or "guardian"]
        for match in re.finditer(
            r"Start-DefenseClawService -Name (\S+)|Wait-DefenseClawFreshGuardianReconcile",
            block,
        )
    ]
    assert order == ["broker", "sensor helper", "guardian", "gateway", "enumerator"], order

    w36 = _threat_row("W-36")
    assert (
        "demand-start order broker, `DefenseClawSensorHelper`, guardian/fresh reconcile, gateway, enumerator;"
        in w36
    )
    threat = _flat(_read(THREAT_MODEL))
    assert (
        "Activation demand-starts the broker first, then `DefenseClawSensorHelper`, then the guardian"
        in threat
    )
    assert "whose SCM dependency starts `DefenseClawSensorHelper`" not in threat
    assert "(after its `DefenseClawSensorHelper` dependency)" not in threat

    deployment = _flat(_read(DEPLOYMENT_DOC))
    assert (
        "Activation then demand-starts the broker and the sensor helper, makes the guardian demand-startable"
        in deployment
    )
    assert "Activation then makes only the guardian demand-startable" not in deployment


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


def test_certification_doc_lists_the_protected_staging_set() -> None:
    staging = _powershell_function(_read(HARNESS), "Initialize-ProtectedCertificationSources")
    labels = set(re.findall(r"'stage-(?!upgrade-)([\w-]+)'", staging))
    documented = {
        "enterprise-installer": "installer",
        "enterprise-module": "adjacent module",
        "broker": "broker",
        "gateway": "gateway",
        "acp": "ACP",
        "hook": "hook",
        "sensor-helper": "sensor helper",
        "cli": "required CLI",
        "normal-mode-cli-launcher": "normal-mode CLI launcher",
        "normal-mode-cli-wheel": "wheel",
    }
    assert labels == set(documented), labels
    # The provider library is checked where it is installed, not copied.
    assert "Assert-CertificationProviderLibraryCurrent" in staging

    flat = _flat(_read(CERTIFICATION_DOC))
    start = flat.index("Before any installer action, the harness byte-copies")
    # Up to the upgrade set, which the upgrade test above checks.
    sentence = flat[start : flat.index("-binary upgrade set", start)]
    for label, name in documented.items():
        assert name in sentence, label
    assert "The managed credential provider library `cmidapi.dll` is not copied" in flat
    assert "byte-copies the installer, adjacent module, gateway, hook, required CLI, and" not in flat


def test_upgrade_docs_name_every_binary_a_cli_upgrade_replaces() -> None:
    flags = re.findall(
        r'flags\.StringVar\(&opts\.\w+Binary, "([\w-]+)-binary"',
        _read(LIFECYCLE_CLI),
    )
    assert set(flags) == {"broker", "gateway", "acp", "hook", "sensor-helper", "cli"}, flags
    names = {"broker": "broker", "gateway": "gateway", "acp": "ACP", "hook": "hook", "sensor-helper": "sensor helper"}

    for path, lead in (
        (CERTIFICATION_DOC, "it remains valid for an upgrade that omits `--cli-binary`"),
        (DEPLOYMENT_DOC, "Running the installed CLI is still valid for an upgrade that omits `--cli-binary`"),
    ):
        flat = _flat(_read(path))
        start = flat.index(lead)
        sentence = flat[start : flat.index(".", start)]
        for flag in flags:
            if flag != "cli":
                assert names[flag] in sentence, (path.name, flag)
        assert "broker/gateway/hook-only" not in flat, path.name


def test_codex_requirements_doc_names_the_guardian_reconcile() -> None:
    module = _read(MODULE)
    assert re.search(r"enterprise hooks watch --manifest \"\{1\}\" --interval 1m'", module)

    doc = _flat(_read(DEPLOYMENT_DOC))
    section = doc[doc.index("## Native Windows Codex managed hooks") :]
    section = section[: section.index("## ", 3)]
    assert "the guardian checks the file every minute" in section
    assert "an edit is therefore recorded as the DefenseClaw version within about a minute" in section
    assert "Repairing a changed `requirements.toml` does not revert an administrator's edit" in section
    assert "Reconcile runs on install and repair, and each time a Codex user is enrolled." not in section


def test_codex_requirements_doc_limits_the_signed_out_deferral_to_protected_targets() -> None:
    # A never-protected target goes straight to Install on every guardian
    # cycle, and the Codex install reconciles requirements.toml before it
    # impersonates the target user, so a signed-out user does not stop the
    # reconcile. Only an already protected target waits for a session.
    repair = _go_function(_read(HOOK_RECONCILE), "enterpriseHookVerifyOrRepairTarget")
    never_protected = repair[repair.index("if !previouslyProtected {") :]
    assert never_protected.index("enterpriseHookReconcileInstaller(") < never_protected.index(
        "enterpriseHookReconcileSessionAvailable("
    )
    install = _go_function(_read(CODEX_INSTALL), "installWindowsCodexManagedResult")
    assert install.index("windowsCodexRequirementsReconciler(machineOpts)") < install.index(
        "windowsEnterpriseTargetImpersonation("
    )

    doc = _flat(_read(DEPLOYMENT_DOC))
    section = doc[doc.index("## Native Windows Codex managed hooks") :]
    section = section[: section.index("## ", 3)]
    assert "With no enrolled Codex user signed in, the guardian defers that repair" not in section
    assert "It can be recorded the same way with nobody signed in" in section
    assert "while an enabled Codex target has never been protected" in section
    assert (
        "only when every enabled Codex target is already protected and none of their users is signed in"
        in section
    )


def test_unavailable_action_docs_cover_single_request_fail_open() -> None:
    doc = _flat(_read(DEPLOYMENT_DOC))
    start = doc.index("In `managed_enterprise`, AI Defense is the only decision-maker.")
    # The outage paragraph is followed by its own per-request paragraph, so a
    # change to the outage paragraph and this one merge without a conflict.
    section = doc[start : doc.index("Set ownership and start the service", start)]
    per_request = section[section.index("The allow default applies to each request, not only to outages.") :]
    assert "an HTTP error for that one request" in per_request
    assert "rate limited" in per_request
    assert "a response DefenseClaw cannot read" in per_request
    assert "The default therefore fails open per request" in per_request
    assert "switches the machine-wide Secure Client state to `DEGRADED`" in per_request
    assert "set `cisco_ai_defense.unavailable_action: block` and run the connectors in `action` mode" in per_request
    assert section.count("The default therefore fails open per request") == 1

    threat = _flat(_read(THREAT_MODEL))
    residuals = threat[threat.index("## Residual risks and deployment dependencies") : threat.index("## Certification gate")]
    assert "`cisco_ai_defense.unavailable_action: allow`" in residuals
    assert "must set `unavailable_action: block`" in residuals


def test_claude_attestation_docs_match_the_actions_the_module_accepts() -> None:
    module = _read(MODULE)
    guard = re.search(
        r"if \(\$AttestClaudeEffectivePolicy -and\s+\$Action -notin @\(([^)]*)\)\)",
        module,
    )
    assert guard, "module -AttestClaudeEffectivePolicy action guard not found"
    accepted = set(re.findall(r"'(\w+)'", guard.group(1)))
    assert "Install" not in accepted
    assert "Repair" in accepted

    deployment = _flat(_read(DEPLOYMENT_DOC))
    certification = _flat(_read(CERTIFICATION_DOC))
    w34 = _threat_row("W-34")
    if "Upgrade" in accepted:
        # The docs must not promise that only Repair can persist evidence.
        for text in (deployment, certification, w34):
            assert "Only production `Repair -AttestClaudeEffectivePolicy`" not in text
        assert "an attested Upgrade to a release whose hook binary or Claude policy changed records verified evidence" in deployment
        assert "an attested Upgrade binds whatever policy and hook binary it installs" in certification
        assert "Production `Upgrade` or `Repair` with `-AttestClaudeEffectivePolicy`" in w34
    else:
        assert "`Upgrade` also accepts the flag" not in deployment
        assert "`Upgrade` also accepts `-AttestClaudeEffectivePolicy`" not in certification
        assert "Production `Upgrade` or `Repair`" not in w34
    assert "DefenseClaw cannot check which bytes the proof ran against" in deployment


def test_cursor_foreign_hook_approval_doc_states_what_a_digest_trusts() -> None:
    doc = _flat(_read(DEPLOYMENT_DOC))
    # One paragraph describes what an approval digest covers. The text ships
    # with the change that binds digests to scope and event (sc/fix-g5).
    assert doc.count("The digest covers") <= 1
    assert "The digest covers the registration text DefenseClaw reads from the hooks file" not in doc
    if "func foreignHookApprovalDigest(" not in _read(FOREIGN_HOOKS):
        pytest.skip("Cursor approval digests are not scope-bound in this tree; the doc text ships with that change")
    assert doc.count("The digest covers the handler registration") == 1
    assert "its event and its scope" in doc
    assert "It does not cover the script the command runs" in doc
    assert (
        "Approve only handlers whose command is an absolute path to an executable that standard users cannot modify"
        in doc
    )


def test_threat_model_covers_the_secure_client_gui_ipc_boundary() -> None:
    assert (ROOT / "internal/ipc/winpeer_auth.go").is_file()
    row = [
        line
        for line in _read(THREAT_MODEL).splitlines()
        if line.startswith("| W-") and "defenseclaw_ipc.sock" in line
    ]
    assert len(row) == 1, row
    assert "Admission authenticates the executable, not the user" in row[0]

    threat = _flat(_read(THREAT_MODEL))
    residuals = threat[threat.index("## Residual risks and deployment dependencies") : threat.index("## Certification gate")]
    assert "Secure Client GUI IPC admission" in residuals
    assert "with no session or SID filter" in residuals
    assert "it is not a boundary against the signed-in user or between sessions" in residuals

    deployment = _flat(_read(DEPLOYMENT_DOC))
    assert "on a multi-session host each user's GUI also sees other sessions' approval notifications" in deployment
