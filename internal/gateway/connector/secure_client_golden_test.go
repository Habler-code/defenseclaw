// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// Secure Client golden: the Windows managed_enterprise Codex machine policy
// that production Secure Client installs publish to
// %ProgramData%\OpenAI\Codex\requirements.toml. The reconcile runs on every
// platform (it is pure string/TOML work), so the fixture is enforced by the
// Linux, macOS, and Windows Go suites alike. See
// testdata/secure_client_golden/README.md.

const secureClientGoldenAdminRequirements = `# Administrator-managed Codex requirements.
# These comments and this ordering are part of the pinned current behavior.
allowed_approval_policies = ["on-request", "never"]
allowed_sandbox_modes = ["read-only", "workspace-write"]

[features]
web_search = false

[[hooks.PreToolUse]]
matcher = "Bash"

[[hooks.PreToolUse.hooks]]
type = "command"
command = 'C:\Tools\audit-hook.exe'
timeout = 30
`

func secureClientGoldenCodexOptions() WindowsCodexMachineRequirementsOptions {
	return WindowsCodexMachineRequirementsOptions{
		RequirementsPath:   `C:\ProgramData\OpenAI\Codex\requirements.toml`,
		ManagedDir:         `C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw\bin`,
		HookBinary:         `C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw\bin\defenseclaw-hook.exe`,
		OwnershipPath:      `C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw\install\codex-requirements-ownership.json`,
		ManagedStatePath:   `C:\ProgramData\OpenAI\Codex\.defenseclaw-managed-hooks.state`,
		GatewayAddr:        "127.0.0.1:18970",
		GatewayServiceName: "DefenseClawGateway",
		CodexTargetEnabled: true,
	}
}

// secureClientGoldenSystemDirectory replaces the OS-reported System32 path
// (C:\Windows\system32 from the Windows API, C:\Windows\System32 elsewhere)
// with a token so one fixture serves every platform. The directory is
// Windows-provided, not DefenseClaw behavior.
const secureClientGoldenSystemDirectory = "%SYSTEM32%"

func secureClientGoldenNormalizeSystemDirectory(data []byte) []byte {
	return bytes.ReplaceAll(data, []byte(trustedWindowsSystemDirectory()), []byte(secureClientGoldenSystemDirectory))
}

func TestSecureClientGoldenCodexMachineRequirements(t *testing.T) {
	opts := secureClientGoldenCodexOptions()
	for _, tc := range []struct {
		name   string
		input  string
		golden string
	}{
		{name: "empty", input: "", golden: "windows/codex_requirements_empty.toml"},
		{name: "admin", input: secureClientGoldenAdminRequirements, golden: "windows/codex_requirements_admin.toml"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rendered, changed, err := reconcileWindowsCodexRequirements([]byte(tc.input), opts)
			if err != nil {
				t.Fatalf("reconcile: %v", err)
			}
			if !changed {
				t.Fatal("first reconcile reported no change")
			}
			testenv.CompareSecureClientGoldenBytes(t, tc.golden, secureClientGoldenNormalizeSystemDirectory(rendered))

			again, changedAgain, err := reconcileWindowsCodexRequirements(rendered, opts)
			if err != nil {
				t.Fatalf("second reconcile: %v", err)
			}
			if changedAgain || string(again) != string(rendered) {
				t.Fatal("reconcile is not idempotent on its own output")
			}
			if err := verifyWindowsCodexRequirementsBytes(rendered, opts); err != nil {
				t.Fatalf("verify rendered requirements: %v", err)
			}
		})
	}

	var refusals []map[string]string
	for _, tc := range []struct {
		name  string
		input string
	}{
		{name: "managed_hooks_only_false", input: "allow_managed_hooks_only = false\n"},
		{name: "features_hooks_false", input: "[features]\nhooks = false\n"},
		{name: "hooks_state_present", input: "[hooks]\nstate = \"enabled\"\n"},
		{name: "foreign_managed_dir", input: "[hooks]\nwindows_managed_dir = 'C:\\Elsewhere'\n"},
	} {
		_, _, err := reconcileWindowsCodexRequirements([]byte(tc.input), opts)
		row := map[string]string{"case": tc.name}
		if err != nil {
			row["error"] = err.Error()
		}
		refusals = append(refusals, row)
	}

	groups := make([]map[string]any, 0, len(codexHookGroups))
	for _, group := range codexHookGroups {
		groups = append(groups, map[string]any{
			"event":   group.eventType,
			"matcher": group.matcher,
			"timeout": group.timeout,
		})
	}
	testenv.CompareSecureClientGoldenJSON(t, "windows/codex_requirements_contract.json", map[string]any{
		"hook_groups":          groups,
		"managed_hook_command": strings.ReplaceAll(windowsCodexManagedHookCommand(opts.HookBinary), trustedWindowsSystemDirectory(), secureClientGoldenSystemDirectory),
		"refusals":             refusals,
		"report":               windowsCodexMachineReport("install", opts),
		"schema_version":       WindowsCodexMachineRequirementsSchemaVersion,
		"state_file":           windowsCodexManagedStateFile,
		"lock_file":            windowsCodexManagedLockFile,
		"environment_contract": map[string]string{
			"approved_agent_clients_enforced": WindowsApprovedAgentClientsEnforcedEnv,
			"claude_effective_policy":         WindowsClaudeEffectivePolicyVerifiedEnv,
			"gateway_service_name":            WindowsGatewayServiceNameEnv,
			"claude_unverified_reason":        WindowsClaudeEffectivePolicyUnverifiedReason,
		},
	})
}
