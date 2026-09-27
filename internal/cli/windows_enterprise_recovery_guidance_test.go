// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

// The dc-win failure (WIN-F12/WIN-F17): an install whose rollback could not
// retire a user's managed runtime generations.
const windowsEnterpriseRelaxedHooksFailure = `Install failed (LocalSystem guardian restarted but did not publish fresh required coverage within 90 seconds); ` +
	`rollback also failed and pending recovery was retained: managed-hook lifecycle snapshot retire failed: ` +
	`retire amp managed runtime generations for SID S-1-5-21-1-2-3-1017: ` +
	`managed Windows DACL on C:\Users\dcw-std1\.defenseclaw\hooks has 2 ACEs, expected 7`

func TestWindowsEnterpriseStandaloneErrorTextStatesPermissionFailuresPlainly(t *testing.T) {
	for _, tc := range []struct {
		name, message, want string
		internal            bool
	}{
		{
			name:     "ACE count",
			message:  windowsEnterpriseRelaxedHooksFailure,
			want:     `retire amp managed runtime generations for SID S-1-5-21-1-2-3-1017: the permissions on C:\Users\dcw-std1\.defenseclaw\hooks are not the ones DefenseClaw set`,
			internal: true,
		},
		{
			name:     "unreadable descriptor",
			message:  `managed-hook lifecycle snapshot retire failed: inspect Windows security descriptor for C:\Users\dcw-std1\.defenseclaw\hooks: Access is denied.`,
			want:     `managed-hook lifecycle snapshot retire failed: DefenseClaw could not read the permissions on C:\Users\dcw-std1\.defenseclaw\hooks (Access is denied.)`,
			internal: true,
		},
		{
			name:     "path before the descriptor clause",
			message:  `repair failed: C:\ProgramData\Cisco\DefenseClaw\hook-guardian: inspect Windows security descriptor: Access is denied`,
			want:     `repair failed: DefenseClaw could not read the permissions on C:\ProgramData\Cisco\DefenseClaw\hook-guardian (Access is denied)`,
			internal: true,
		},
		{
			name:     "unknown internal clause",
			message:  `Uninstall failed (x); rollback also failed: enterprise hooks: managed runtime machine file DACL has a noncanonical ACE count: C:\ProgramData\Cisco\DefenseClaw-HookRuntime\hook.json`,
			want:     `Uninstall failed (x); rollback also failed: enterprise hooks: DefenseClaw could not verify or apply the permissions on C:\ProgramData\Cisco\DefenseClaw-HookRuntime\hook.json`,
			internal: true,
		},
		{
			name:     "no internal detail",
			message:  "Repair recovered a failed initial install; run Install or Uninstall -Purge",
			want:     "Repair recovered a failed initial install; run Install or Uninstall -Purge",
			internal: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, internal := windowsEnterpriseStandaloneErrorText(tc.message)
			if internal != tc.internal {
				t.Fatalf("internal = %v, want %v", internal, tc.internal)
			}
			if tc.internal && !strings.HasSuffix(got, tc.want) {
				t.Fatalf("text = %q, want suffix %q", got, tc.want)
			}
			if !tc.internal && got != tc.want {
				t.Fatalf("text = %q, want %q", got, tc.want)
			}
			if windowsEnterpriseSecurityDetailPattern.MatchString(got) {
				t.Fatalf("text still carries internal detail: %q", got)
			}
		})
	}
	got, _ := windowsEnterpriseStandaloneErrorText(windowsEnterpriseRelaxedHooksFailure)
	if !strings.HasPrefix(got, "Install failed (") || !strings.Contains(got, "rollback also failed and pending recovery was retained") {
		t.Fatalf("the plain text lost what failed: %q", got)
	}
}

func TestWindowsEnterpriseStandaloneNextStepNamesTheRecoveryCommand(t *testing.T) {
	const setup = "DefenseClawSetup-Enterprise-Standalone-x64.exe"
	if got := windowsEnterpriseStandaloneNextStep("ensure", `C:\Staging\config.yaml`, false, nil, nil); got != "" {
		t.Fatalf("a rolled-back failure got a recovery step: %q", got)
	}
	for _, tc := range []struct {
		name    string
		action  string
		config  string
		runs    []windowsEnterpriseRecoveryGatewayRun
		refusal *windowsEnterpriseRecoveryGatewayRefusal
		want    []string
	}{
		{
			name:    "not LocalSystem",
			action:  "ensure",
			config:  `C:\Staging\config.yaml`,
			refusal: &windowsEnterpriseRecoveryGatewayRefusal{Action: "retire", Code: "not_local_system"},
			want:    []string{"run the same Setup as LocalSystem", setup + ` /ensure CONFIG=C:\Staging\config.yaml JSON=1`},
		},
		{
			name:    "the Setup gateway is the one that failed",
			action:  "repair",
			refusal: &windowsEnterpriseRecoveryGatewayRefusal{Action: "retire", Code: "same_binary"},
			want:    []string{"run a newer DefenseClaw Setup", setup + " /ensure CONFIG=<config.yaml> JSON=1"},
		},
		{
			name:    "untrusted payload",
			action:  "install",
			config:  `C:\Program Data\config.yaml`,
			refusal: &windowsEnterpriseRecoveryGatewayRefusal{Action: "retire", Code: "untrusted", Message: "not admitted by the standalone payload trust policy"},
			want:    []string{"did not pass the payload trust check (not admitted", `CONFIG="C:\Program Data\config.yaml"`},
		},
		{
			name:    "an older Setup release",
			action:  "ensure",
			config:  `C:\Staging\config.yaml`,
			refusal: &windowsEnterpriseRecoveryGatewayRefusal{Action: "retire", Code: "older_release", Message: "the running Setup gateway is release 1.0.41, older than the staged gateway's release 1.0.43"},
			want:    []string{"older release than the one that staged the transaction (the running Setup gateway is release 1.0.41", "that release or a newer one", setup + ` /ensure CONFIG=C:\Staging\config.yaml JSON=1`},
		},
		{
			name:    "a release that cannot be read",
			action:  "uninstall",
			refusal: &windowsEnterpriseRecoveryGatewayRefusal{Action: "restore", Code: "version_unknown", Message: "the release of the running Setup gateway (unavailable) or of the staged gateway (1.0.40) is not a readable release version"},
			want:    []string{"could not be read (the release of the running Setup gateway", "send the lifecycle log to DefenseClaw support", setup + " /uninstall JSON=1"},
		},
		{
			name:   "uninstall",
			action: "uninstall",
			want:   []string{setup + " /uninstall JSON=1", "this release or a newer one"},
		},
		{
			name:   "recovery already used the verified gateway",
			action: "ensure",
			config: `C:\Staging\config.yaml`,
			runs:   []windowsEnterpriseRecoveryGatewayRun{{Action: "retire", Binary: `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-gateway.exe`, Outcome: "failed"}},
			want:   []string{"still did not finish", "send the lifecycle log to DefenseClaw support"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := windowsEnterpriseStandaloneNextStep(tc.action, tc.config, true, tc.runs, tc.refusal)
			if !strings.Contains(got, "Next step: ") || !strings.Contains(got, "LocalSystem") {
				t.Fatalf("next step %q", got)
			}
			for _, want := range tc.want {
				if !strings.Contains(got, want) {
					t.Fatalf("next step %q does not contain %q", got, want)
				}
			}
		})
	}
}

func TestWindowsEnterpriseRecoveryGatewayEvidenceBecomesWarnings(t *testing.T) {
	runs := decodeWindowsEnterpriseRecoveryGatewayRuns(json.RawMessage(`[{
		"action":"retire",
		"binary":"C:\\Program Files\\Cisco\\DefenseClaw\\bin\\defenseclaw-gateway.exe",
		"source":"C:\\ProgramData\\DefenseClaw-Enterprise-Setup-0f\\defenseclaw-gateway.exe",
		"sha256":"c15794a6a68372461b8fb88be839a3304094dbbef21f19bc9ef6d39dd5a32635",
		"trust":"hash_pinned","signer_thumbprint":"","product_version":"1.0.43",
		"identity":"NT AUTHORITY\\SYSTEM","replaced_sha256":"aa","staged_version":"1.0.40",
		"reason":"staged_gateway_failed",
		"staged_error":"managed-hook lifecycle snapshot retire failed: managed Windows DACL on C:\\Users\\u\\.defenseclaw\\hooks has 2 ACEs, expected 7",
		"outcome":"succeeded","error":""}]`))
	if len(runs) != 1 {
		t.Fatalf("runs = %+v", runs)
	}
	refusal := decodeWindowsEnterpriseRecoveryGatewayRefusal(json.RawMessage(`{"action":"retire","code":"not_local_system","message":"recovery runs the Setup gateway only as LocalSystem"}`))
	warnings := windowsEnterpriseRecoveryGatewayWarnings(runs, refusal)
	if len(warnings) != 2 || warnings[0].Code != "recovery_gateway_fallback" || warnings[1].Code != "recovery_gateway_not_used" {
		t.Fatalf("warnings = %+v", warnings)
	}
	for _, want := range []string{
		`binary C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-gateway.exe`,
		`copied from C:\ProgramData\DefenseClaw-Enterprise-Setup-0f\defenseclaw-gateway.exe`,
		"sha256 c15794a6a68372461b8fb88be839a3304094dbbef21f19bc9ef6d39dd5a32635",
		"trust hash_pinned", ", version 1.0.43, ", "replaced staged sha256 aa, staged version 1.0.40", `as NT AUTHORITY\SYSTEM`,
		"because the staged gateway failed it", "outcome succeeded",
		`the permissions on C:\Users\u\.defenseclaw\hooks are not the ones DefenseClaw set`,
	} {
		if !strings.Contains(warnings[0].Message, want) {
			t.Fatalf("fallback warning %q does not contain %q", warnings[0].Message, want)
		}
	}
	if windowsEnterpriseSecurityDetailPattern.MatchString(warnings[0].Message) {
		t.Fatalf("fallback warning repeats internal detail: %q", warnings[0].Message)
	}
	if !strings.Contains(warnings[1].Message, "(not_local_system): recovery runs the Setup gateway only as LocalSystem") {
		t.Fatalf("refusal warning %q", warnings[1].Message)
	}

	// Lenient decoding: one object is one run; malformed values and runs
	// without an action or binary are ignored.
	if got := decodeWindowsEnterpriseRecoveryGatewayRuns(json.RawMessage(`{"action":"restore","binary":"C:\\x\\bin\\defenseclaw-gateway.exe"}`)); len(got) != 1 {
		t.Fatalf("single object: %+v", got)
	}
	for _, raw := range []string{``, `null`, `"x"`, `[{"action":"retire"}]`, `{"value":[],"Count":0}`} {
		if got := decodeWindowsEnterpriseRecoveryGatewayRuns(json.RawMessage(raw)); len(got) != 0 {
			t.Fatalf("%q decoded %+v", raw, got)
		}
	}
	if got := decodeWindowsEnterpriseRecoveryGatewayRefusal(json.RawMessage(`{"action":"retire"}`)); got != nil {
		t.Fatalf("a refusal without a code decoded: %+v", got)
	}
}

func TestWindowsEnterpriseStandaloneLifecycleActions(t *testing.T) {
	for action, want := range map[string]bool{
		"install": true, "upgrade": true, "repair": true, "reconcile": true, "ensure": true, "uninstall": true,
		"status": false, "verify": false,
	} {
		if got := windowsEnterpriseStandaloneLifecycleAction(action); got != want {
			t.Fatalf("%s: %v, want %v", action, got, want)
		}
	}
}
