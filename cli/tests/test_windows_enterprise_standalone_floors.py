# Copyright 2026 Cisco Systems, Inc. and its affiliates
# SPDX-License-Identifier: Apache-2.0
"""The standalone Windows Claude floor follows the hook-contract table.

The lifecycle module records the Claude client floor in application-control
evidence, deployment metadata and status. For the standalone profile it must
equal the lowest Claude hook contract in internal/gateway/connector (the Go
guardian enforces the same floor); the Secure Client value is unchanged.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MODULE = ROOT / "packaging" / "windows" / "DefenseClawEnterprise.psm1"
HOOK_CONTRACTS = ROOT / "internal" / "gateway" / "connector" / "hook_contract.go"


def _version_key(value: str) -> tuple[int, ...]:
    return tuple(int(part) for part in value.split("."))


def _lowest_contract(connector: str) -> str:
    text = HOOK_CONTRACTS.read_text(encoding="utf-8")
    start = text.index(f'\t"{connector}": {{')
    following = re.search(r'\n\t"[a-z]+": \{', text[start + 1 :])
    block = text[start : start + 1 + following.start()] if following else text[start:]
    versions = re.findall(r'MinAgentVersion:\s+"([0-9.]+)"', block)
    assert versions, f"no {connector} hook contracts found"
    return min(versions, key=_version_key)


def _floor_function() -> str:
    text = MODULE.read_text(encoding="utf-8-sig")
    match = re.search(
        r"^function Get-DefenseClawClaudeMinimumClientVersion \{\n(.*?)^\}",
        text,
        re.MULTILINE | re.DOTALL,
    )
    assert match, "Get-DefenseClawClaudeMinimumClientVersion is missing"
    return match.group(1)


def test_standalone_claude_floor_is_the_lowest_claude_hook_contract() -> None:
    body = _floor_function()
    standalone = re.search(
        r"if \(Test-DefenseClawStandaloneProfile\) \{\s*return '([0-9.]+)'", body
    )
    assert standalone, body
    assert standalone.group(1) == _lowest_contract("claudecode")


def test_secure_client_claude_floor_is_unchanged() -> None:
    body = _floor_function()
    returns = re.findall(r"return '([0-9.]+)'", body)
    assert returns[-1] == "2.1.152"


def test_module_records_the_floor_only_through_the_helper() -> None:
    text = MODULE.read_text(encoding="utf-8-sig")
    literal_uses = [
        line
        for line in text.splitlines()
        if "2.1.15" in line and "return '" not in line
    ]
    assert literal_uses == []
