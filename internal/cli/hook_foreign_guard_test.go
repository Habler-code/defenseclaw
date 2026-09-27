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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

const foreignGuardHookBinary = "/opt/defenseclaw/bin/defenseclaw-hook"

type foreignGuardFixture struct {
	home    string
	project string
	summary *enterprisepolicy.PublicPolicy
	loadErr error
}

func newForeignGuardFixture(t *testing.T, mode string) *foreignGuardFixture {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fixture uses unix hook command forms")
	}
	fixture := &foreignGuardFixture{home: t.TempDir()}
	fixture.project = filepath.Join(fixture.home, "work", "repo")
	if err := os.MkdirAll(filepath.Join(fixture.project, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	fixture.summary = &enterprisepolicy.PublicPolicy{
		SchemaVersion: 1,
		HookBinary:    foreignGuardHookBinary,
		Connectors: map[string]enterprisepolicy.PublicConnectorPolicy{
			"cursor": {Route: enterprisepolicy.RouteMachinePolicy, ForeignHooks: mode, Guard: true},
		},
	}
	previousPath, previousLoad, previousHomes := hookForeignGuardSummaryPath, hookForeignGuardLoad, hookForeignGuardHomes
	hookForeignGuardSummaryPath = func() (string, bool) { return "/etc/defenseclaw/machine-policy.json", true }
	hookForeignGuardLoad = func(string) (*enterprisepolicy.PublicPolicy, error) {
		if fixture.loadErr != nil {
			return nil, fixture.loadErr
		}
		if fixture.summary == nil {
			return nil, enterprisepolicy.ErrNoPublicPolicy
		}
		return fixture.summary, nil
	}
	hookForeignGuardHomes = func() []string { return []string{fixture.home} }
	t.Cleanup(func() {
		hookForeignGuardSummaryPath, hookForeignGuardLoad, hookForeignGuardHomes = previousPath, previousLoad, previousHomes
	})
	return fixture
}

func (f *foreignGuardFixture) write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (f *foreignGuardFixture) run(t *testing.T, managed bool) (hookexec.Options, string, string) {
	t.Helper()
	payload := `{"hook_event_name":"preToolUse","cwd":"` + filepath.Join(f.project, "src") + `","tool_name":"Shell"}`
	var stderr bytes.Buffer
	opts := hookexec.Options{Connector: "cursor", ManagedEnterprise: managed, Stdin: strings.NewReader(payload), Stderr: &stderr}
	applyEnterpriseForeignHookGuard(&opts)
	replayed, err := io.ReadAll(opts.Stdin)
	if err != nil {
		t.Fatal(err)
	}
	if string(replayed) != payload {
		t.Fatalf("hookexec must receive the identical payload, got %q", replayed)
	}
	return opts, stderr.String(), payload
}

func TestForeignHookGuardDenyAllowMatrix(t *testing.T) {
	fixture := newForeignGuardFixture(t, config.ForeignHooksRemove)
	if opts, _, _ := fixture.run(t, true); opts.ManagedRuntimeFailure != "" {
		t.Fatalf("no foreign hooks must allow: %q", opts.ManagedRuntimeFailure)
	}

	projectHooks := filepath.Join(fixture.project, ".cursor", "hooks.json")
	fixture.write(t, projectHooks, `{"version": 1, "hooks": {"preToolUse": [{"command": "./rewrite.sh"}]}}`)
	for _, managed := range []bool{true, false} {
		opts, _, _ := fixture.run(t, managed)
		if !opts.ManagedEnterprise || !strings.Contains(opts.ManagedRuntimeFailure, "enterprise_foreign_hook_blocked") || !strings.Contains(opts.ManagedRuntimeFailure, projectHooks) {
			t.Fatalf("managed=%v: a project hook found through the payload cwd must deny: %+v", managed, opts)
		}
	}

	decision := enterprisepolicy.EvaluateForeignHooks(enterprisepolicy.GuardRequest{
		Connector: "cursor", Home: fixture.home, WorkingDir: fixture.project, HookBinary: foreignGuardHookBinary,
		Policy: fixture.summary.Connectors["cursor"],
	})
	allowed := fixture.summary.Connectors["cursor"]
	allowed.AllowedHooks = []string{decision.Findings[0].Digest}
	fixture.summary.Connectors["cursor"] = allowed
	if opts, _, _ := fixture.run(t, true); opts.ManagedRuntimeFailure != "" {
		t.Fatalf("an allowlisted digest must allow: %q", opts.ManagedRuntimeFailure)
	}

	allowed.AllowedHooks = nil
	allowed.ForeignHooks = config.ForeignHooksReport
	fixture.summary.Connectors["cursor"] = allowed
	opts, stderr, _ := fixture.run(t, true)
	if opts.ManagedRuntimeFailure != "" || !strings.Contains(stderr, "reports it but allows it") {
		t.Fatalf("report mode must warn and allow: %q %q", opts.ManagedRuntimeFailure, stderr)
	}

	allowed.Guard = false
	fixture.summary.Connectors["cursor"] = allowed
	if opts, _, _ := fixture.run(t, true); opts.ManagedRuntimeFailure != "" {
		t.Fatalf("a connector without the guard must allow: %q", opts.ManagedRuntimeFailure)
	}
}

func TestForeignHookGuardIsInertWithoutStandaloneSummary(t *testing.T) {
	fixture := newForeignGuardFixture(t, config.ForeignHooksRemove)
	fixture.summary = nil
	fixture.write(t, filepath.Join(fixture.project, ".cursor", "hooks.json"), `{"version": 1, "hooks": {"preToolUse": [{"command": "./rewrite.sh"}]}}`)
	payload := strings.NewReader(`{"cwd":"/tmp"}`)
	opts := hookexec.Options{Connector: "cursor", ManagedEnterprise: true, Stdin: payload}
	applyEnterpriseForeignHookGuard(&opts)
	if opts.ManagedRuntimeFailure != "" || opts.Stdin != io.Reader(payload) || payload.Len() != len(`{"cwd":"/tmp"}`) {
		t.Fatalf("Secure Client and unmanaged hosts (no summary) must be untouched: %+v", opts)
	}
	previous := hookForeignGuardSummaryPath
	hookForeignGuardSummaryPath = func() (string, bool) { return "", false }
	defer func() { hookForeignGuardSummaryPath = previous }()
	opts = hookexec.Options{Connector: "cursor", ManagedEnterprise: false, Stdin: payload}
	applyEnterpriseForeignHookGuard(&opts)
	if opts.ManagedEnterprise || opts.ManagedRuntimeFailure != "" {
		t.Fatalf("a host without a standalone layout must be untouched: %+v", opts)
	}
}

func TestForeignHookGuardFailsClosedOnUntrustedSummary(t *testing.T) {
	fixture := newForeignGuardFixture(t, config.ForeignHooksRemove)
	fixture.loadErr = errors.New("machine policy summary is group-writable")
	opts := hookexec.Options{Connector: "cursor", Stdin: strings.NewReader("{}")}
	applyEnterpriseForeignHookGuard(&opts)
	if !opts.ManagedEnterprise || opts.ManagedRuntimeFailure != "enterprise_machine_policy_summary_untrusted" {
		t.Fatalf("an untrusted summary must fail closed: %+v", opts)
	}
	existing := hookexec.Options{Connector: "cursor", ManagedEnterprise: true, ManagedRuntimeFailure: "enterprise_managed_runtime_invalid"}
	applyEnterpriseForeignHookGuard(&existing)
	if existing.ManagedRuntimeFailure != "enterprise_managed_runtime_invalid" {
		t.Fatalf("an earlier runtime failure must be preserved: %q", existing.ManagedRuntimeFailure)
	}
}

func TestForeignHookGuardTreatsPerUserRegistrationAsOwned(t *testing.T) {
	fixture := newForeignGuardFixture(t, config.ForeignHooksRemove)
	script := filepath.Join(fixture.home, ".defenseclaw", "hooks", "cursor-hook.sh")
	machine := `'` + foreignGuardHookBinary + `' hook --connector cursor --enterprise-managed`
	document, _ := json.Marshal(map[string]any{"version": 1, "hooks": map[string]any{
		"preToolUse": []any{map[string]any{"command": script}, map[string]any{"command": machine}},
	}})
	fixture.write(t, filepath.Join(fixture.home, ".cursor", "hooks.json"), string(document))
	if opts, _, _ := fixture.run(t, false); opts.ManagedRuntimeFailure != "" {
		t.Fatalf("DefenseClaw's own per-user and machine registrations are not foreign: %q", opts.ManagedRuntimeFailure)
	}
}

func TestForeignHookGuardDenialUsesVendorBlockResponse(t *testing.T) {
	fixture := newForeignGuardFixture(t, config.ForeignHooksRemove)
	fixture.summary.Connectors["claudecode"] = enterprisepolicy.PublicConnectorPolicy{Route: enterprisepolicy.RouteMachinePolicy, ForeignHooks: config.ForeignHooksRemove, Guard: true}
	fixture.write(t, filepath.Join(fixture.project, ".claude", "settings.local.json"), `{"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "./rewrite.sh"}]}]}}`)
	var stdout, stderr bytes.Buffer
	opts := hookexec.Options{
		Connector:         "claudecode",
		Event:             "PreToolUse",
		ManagedEnterprise: true,
		FailMode:          "closed",
		Stdin:             strings.NewReader(`{"hook_event_name":"PreToolUse","cwd":"` + fixture.project + `","tool_name":"Bash","tool_input":{"command":"ls"}}`),
		Stdout:            &stdout,
		Stderr:            &stderr,
	}
	applyEnterpriseForeignHookGuard(&opts)
	// Claude Code blocks a PreToolUse call on exit 2 and shows stderr.
	if code := hookexec.Run(context.Background(), opts); code != 2 {
		t.Fatalf("the denial must block the tool call: code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stderr.String(), "enterprise_foreign_hook_blocked") || !strings.Contains(stderr.String(), "allowed_hooks") {
		t.Fatalf("the user must see which file to remove or allowlist: %s", stderr.String())
	}
}

// Copilot shows only the structured deny reason, not stderr. A repository
// .github/hooks file (even a sessionStart-only one) makes the managed
// preToolUse and permissionRequest hooks deny before any gateway contact;
// the reason must name that file and the allowlist key.
func TestForeignHookGuardCopilotDenialNamesTheFile(t *testing.T) {
	fixture := newForeignGuardFixture(t, config.ForeignHooksRemove)
	fixture.summary.Connectors["copilot"] = enterprisepolicy.PublicConnectorPolicy{Route: enterprisepolicy.RouteMachinePolicy, ForeignHooks: config.ForeignHooksRemove, Guard: true}
	foreign := filepath.Join(fixture.project, ".github", "hooks", "project.json")
	fixture.write(t, foreign, `{"version":1,"hooks":{"sessionStart":[{"type":"command","bash":"/bin/true"}]}}`)
	for event, field := range map[string]string{"preToolUse": "permissionDecisionReason", "permissionRequest": "message"} {
		var stdout, stderr bytes.Buffer
		opts := hookexec.Options{
			Connector:         "copilot",
			Event:             event,
			ManagedEnterprise: true,
			FailMode:          "closed",
			Stdin:             strings.NewReader(`{"timestamp":1,"cwd":"` + fixture.project + `","toolName":"bash","toolArgs":"{\"command\":\"ls\"}"}`),
			Stdout:            &stdout,
			Stderr:            &stderr,
		}
		applyEnterpriseForeignHookGuard(&opts)
		if code := hookexec.Run(context.Background(), opts); code != 0 {
			t.Fatalf("%s: Copilot reads the structured deny on exit 0: code=%d stderr=%s", event, code, stderr.String())
		}
		var decision map[string]string
		if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &decision); err != nil {
			t.Fatalf("%s: deny body is not JSON: %v: %s", event, err, stdout.String())
		}
		if decision["permissionDecision"] != "deny" && decision["behavior"] != "deny" {
			t.Fatalf("%s: the call must be denied: %s", event, stdout.String())
		}
		message := decision[field]
		if !strings.HasPrefix(message, hookexec.ForeignHookBlockedReasonPrefix) || !strings.Contains(message, foreign) ||
			!strings.Contains(message, "enterprise.machine_policy.connectors.copilot.allowed_hooks") {
			t.Fatalf("%s: the deny reason must name %s and the allowlist key: %q", event, foreign, message)
		}
	}
}
