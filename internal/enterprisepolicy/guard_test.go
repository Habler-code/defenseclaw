// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func guardRequest(t *testing.T, connector string, mode string) GuardRequest {
	t.Helper()
	home := t.TempDir()
	project := filepath.Join(home, "work", "repo")
	if err := os.MkdirAll(filepath.Join(project, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	return GuardRequest{
		Connector:  connector,
		GOOS:       "linux",
		Home:       home,
		WorkingDir: filepath.Join(project, "src"),
		HookBinary: testHookBinary,
		Policy:     PublicConnectorPolicy{Route: RouteFor(connector, "linux"), ForeignHooks: mode, Guard: true},
	}
}

const ownedCursorEntry = `{"type": "command", "command": "'/opt/defenseclaw/bin/defenseclaw-hook' hook --connector cursor --enterprise-managed", "timeout": 30, "failClosed": true}`

func TestGuardDeniesForeignUserAndProjectHooks(t *testing.T) {
	req := guardRequest(t, "cursor", config.ForeignHooksRemove)
	writeFile(t, filepath.Join(req.Home, ".cursor", "hooks.json"), `{"version": 1, "hooks": {"preToolUse": [`+ownedCursorEntry+`]}}`)
	if decision := EvaluateForeignHooks(req); decision.Deny || len(decision.Findings) != 0 {
		t.Fatalf("DefenseClaw's own registration must not be flagged: %+v", decision)
	}
	projectHooks := filepath.Join(req.WorkingDir, "..", ".cursor", "hooks.json")
	writeFile(t, projectHooks, `{"version": 1, "hooks": {"preToolUse": [{"command": "./rewrite-everything.sh"}]}}`)
	decision := EvaluateForeignHooks(req)
	if !decision.Deny || len(decision.Findings) != 1 || decision.Findings[0].Scope != ScopeProject {
		t.Fatalf("a project preToolUse hook must deny: %+v", decision)
	}
	if !strings.Contains(decision.Reason, "enterprise_foreign_hook_blocked") || !strings.Contains(decision.Reason, "allowed_hooks") || !strings.Contains(decision.Reason, decision.Findings[0].Digest) {
		t.Fatalf("deny reason must name the file, digest and allowlist: %s", decision.Reason)
	}

	allowed := req
	allowed.Policy.AllowedHooks = []string{decision.Findings[0].Digest}
	if again := EvaluateForeignHooks(allowed); again.Deny || !again.Findings[0].Allowed {
		t.Fatalf("an allowlisted digest must pass: %+v", again)
	}
	report := req
	report.Policy.ForeignHooks = config.ForeignHooksReport
	if again := EvaluateForeignHooks(report); again.Deny || len(again.Findings) != 1 {
		t.Fatalf("report mode must allow but return findings: %+v", again)
	}
	off := req
	off.Policy.Guard = false
	if again := EvaluateForeignHooks(off); again.Deny || len(again.Findings) != 0 {
		t.Fatalf("a connector without the guard must not scan: %+v", again)
	}
}

func TestGuardFailsClosedOnSymlinkedHookFile(t *testing.T) {
	req := guardRequest(t, "copilot", config.ForeignHooksRemove)
	target := filepath.Join(req.Home, "elsewhere.json")
	writeFile(t, target, `{"hooks": {}}`)
	link := filepath.Join(req.WorkingDir, "..", ".github", "hooks", "evil.json")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	decision := EvaluateForeignHooks(req)
	if !decision.Deny || !strings.Contains(decision.Reason, "cannot be verified") {
		t.Fatalf("a symlinked hook file must fail closed: %+v", decision)
	}
}

func TestGuardCoversCopilotDevinCodexAndPlugins(t *testing.T) {
	copilot := guardRequest(t, "copilot", config.ForeignHooksRemove)
	writeFile(t, filepath.Join(copilot.Home, ".copilot", "hooks", "mine.json"), `{"version": 1, "hooks": {"preToolUse": [{"type": "command", "bash": "./modify-args.sh"}]}}`)
	writeFile(t, filepath.Join(copilot.Home, ".copilot", "hooks", "defenseclaw.json"), `{"version": 1, "hooks": {"preToolUse": [{"type": "command", "bash": "'/opt/defenseclaw/bin/defenseclaw-hook' hook --connector copilot --enterprise-managed --event 'preToolUse'"}]}}`)
	if decision := EvaluateForeignHooks(copilot); !decision.Deny || len(decision.Findings) != 1 {
		t.Fatalf("copilot user hook: %+v", decision)
	}

	devin := guardRequest(t, "devin", config.ForeignHooksRemove)
	writeFile(t, filepath.Join(devin.WorkingDir, "..", ".devin", "hooks.v1.json"), `{"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "./x.sh"}]}]}}`)
	if decision := EvaluateForeignHooks(devin); !decision.Deny {
		t.Fatalf("devin project hook: %+v", decision)
	}

	codex := guardRequest(t, "codex", config.ForeignHooksRemove)
	writeFile(t, filepath.Join(codex.Home, ".codex", "config.toml"), "[[hooks.PreToolUse]]\nmatcher = \"*\"\n\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = \"./rewrite.sh\"\n")
	if decision := EvaluateForeignHooks(codex); !decision.Deny {
		t.Fatalf("codex user hook under preserve: %+v", decision)
	}

	opencode := guardRequest(t, "opencode", config.ForeignHooksRemove)
	writeFile(t, filepath.Join(opencode.Home, ".config", "opencode", "plugins", "defenseclaw.js"), "// DefenseClaw")
	writeFile(t, filepath.Join(opencode.Home, ".config", "opencode", "plugins", "mutate.js"), "export default {}")
	decision := EvaluateForeignHooks(opencode)
	if !decision.Deny || len(decision.Findings) != 1 || !strings.Contains(decision.Reason, "adds a plugin") {
		t.Fatalf("opencode foreign plugin: %+v", decision)
	}
}

func TestGuardHonorsVendorConfigDirOverrides(t *testing.T) {
	req := guardRequest(t, "copilot", config.ForeignHooksRemove)
	custom := filepath.Join(req.Home, "alt-copilot")
	writeFile(t, filepath.Join(custom, "hooks", "x.json"), `{"hooks": {"preToolUse": [{"bash": "./x"}]}}`)
	if decision := EvaluateForeignHooks(req); decision.Deny {
		t.Fatalf("without COPILOT_HOME the alternate dir is not loaded by the agent: %+v", decision)
	}
	req.Getenv = func(key string) string {
		if key == "COPILOT_HOME" {
			return custom
		}
		return ""
	}
	if decision := EvaluateForeignHooks(req); !decision.Deny {
		t.Fatalf("COPILOT_HOME must be scanned when the agent sees it: %+v", decision)
	}
}

func TestCleanupRemovesUserForeignHooksAndBacksUp(t *testing.T) {
	req := guardRequest(t, "cursor", config.ForeignHooksRemove)
	userHooks := filepath.Join(req.Home, ".cursor", "hooks.json")
	original := `{"version": 1, "hooks": {"preToolUse": [` + ownedCursorEntry + `, {"command": "./rewrite.sh"}], "stop": [{"command": "./only-foreign.sh"}]}}`
	writeFile(t, userHooks, original)
	projectHooks := filepath.Join(req.WorkingDir, "..", ".cursor", "hooks.json")
	projectBody := `{"version": 1, "hooks": {"preToolUse": [{"command": "./project.sh"}]}}`
	writeFile(t, projectHooks, projectBody)

	result, err := CleanUserForeignHooks(req, time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Removed) != 2 || result.BackupDir == "" {
		t.Fatalf("cleanup result: %+v", result)
	}
	cleaned := readFile(t, userHooks)
	if strings.Contains(cleaned, "rewrite.sh") || strings.Contains(cleaned, `"stop"`) || !strings.Contains(cleaned, "--connector cursor --enterprise-managed") {
		t.Fatalf("user hooks after cleanup:\n%s", cleaned)
	}
	backups, _ := filepath.Glob(filepath.Join(result.BackupDir, "*-hooks.json"))
	if len(backups) != 1 || readFile(t, backups[0]) != original {
		t.Fatalf("original must be backed up verbatim: %v", backups)
	}
	if readFile(t, projectHooks) != projectBody {
		t.Fatal("project hook files must never be rewritten")
	}
	if decision := EvaluateForeignHooks(req); !decision.Deny || decision.Findings[0].Scope != ScopeProject {
		t.Fatalf("the remaining project hook still denies: %+v", decision)
	}

	report := req
	report.Policy.ForeignHooks = config.ForeignHooksReport
	writeFile(t, userHooks, original)
	if result, _ := CleanUserForeignHooks(report, time.Now()); len(result.Removed) != 0 || readFile(t, userHooks) != original {
		t.Fatal("report mode must not modify user files")
	}
}

func TestPublicPolicyGuardFlags(t *testing.T) {
	opts := testOptions(t)
	opts = withPolicy(opts, "claudecode", func(p *config.EnterpriseConnectorPolicy) { p.ManagedHooksOnly = "preserve" })
	opts = withPolicy(opts, "copilot", func(p *config.EnterpriseConnectorPolicy) { p.ForeignHooks = "allow" })
	summary := BuildPublicPolicy(opts, []string{"codex", "claudecode", "cursor", "copilot", "antigravity", "opencode"})
	want := map[string]bool{"codex": false, "claudecode": true, "cursor": true, "copilot": false, "antigravity": false, "opencode": true}
	for name, guard := range want {
		if summary.Connectors[name].Guard != guard {
			t.Errorf("%s guard = %v, want %v", name, summary.Connectors[name].Guard, guard)
		}
	}
	data, err := MarshalPublicPolicy(summary)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePublicPolicy(data)
	if err != nil || parsed.HookBinary != testHookBinary {
		t.Fatalf("round trip: %v %+v", err, parsed)
	}
	for _, bad := range []string{`{"schema_version": 2, "connectors": {}}`, `{"schema_version": 1, "hook_binary": "/x", "connectors": {}, "token": "x"}`, `{"schema_version": 1, "hook_binary": "/x", "connectors": {"cursor": {"foreign_hooks": "maybe"}}}`} {
		if _, err := ParsePublicPolicy([]byte(bad)); err == nil {
			t.Errorf("ParsePublicPolicy accepted %s", bad)
		}
	}
}
