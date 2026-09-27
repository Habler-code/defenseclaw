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
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// These cases pin the behaviors the live vendor research established.

func withCodexHigherSources(t *testing.T, sources map[string][]byte) {
	t.Helper()
	previous := codexHigherSources
	codexHigherSources = func(Options) (map[string][]byte, error) { return sources, nil }
	t.Cleanup(func() { codexHigherSources = previous })
}

func TestCodexMDMRequirementsOutrankTheSystemFile(t *testing.T) {
	opts := testOptions(t)
	withCodexHigherSources(t, map[string][]byte{"MDM com.openai.codex": []byte("allowed_approval_policies = [\"never\"]\n")})
	state, err := codexTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	if state.Covered || len(state.HigherPrecedence) != 1 || !hasConflict(state, "--format plist") {
		t.Fatalf("an MDM layer without DefenseClaw's hooks must block coverage: %+v", state)
	}

	warn := withPolicy(testOptions(t), "codex", func(p *config.EnterpriseConnectorPolicy) { p.HigherPrecedenceSources = config.HigherPrecedenceWarn })
	state, err = codexTarget{}.Reconcile(warn)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Covered || len(state.HigherPrecedence) != 0 {
		t.Fatalf("warn must report without blocking: %+v", state)
	}

	embedded := testOptions(t)
	plist, err := codexTarget{}.Export(embedded, "plist")
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]string
	if err := json.Unmarshal(plistJSONForTest(t, plist), &payload); err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(payload["requirements_toml_base64"])
	if err != nil {
		t.Fatal(err)
	}
	withCodexHigherSources(t, map[string][]byte{"MDM com.openai.codex": decoded})
	state, err = codexTarget{}.Reconcile(embedded)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Covered {
		t.Fatalf("an MDM layer carrying the exported requirements must be covered: %+v", state)
	}
}

// plistJSONForTest extracts the single string key from the rendered plist.
func plistJSONForTest(t *testing.T, plist []byte) []byte {
	t.Helper()
	text := string(plist)
	const key = "<key>requirements_toml_base64</key>"
	start := strings.Index(text, key)
	if start < 0 {
		t.Fatalf("plist lacks requirements_toml_base64: %s", text)
	}
	rest := text[start+len(key):]
	open := strings.Index(rest, "<string>")
	end := strings.Index(rest, "</string>")
	if open < 0 || end < open {
		t.Fatalf("plist value: %s", text)
	}
	value, _ := json.Marshal(map[string]string{"requirements_toml_base64": rest[open+len("<string>") : end]})
	return value
}

func TestCodexPinsFeaturesHooksInEveryLockMode(t *testing.T) {
	for _, mode := range []string{config.ManagedHooksOnlyEnforce, config.ManagedHooksOnlyPreserve} {
		opts := withPolicy(testOptions(t), "codex", func(p *config.EnterpriseConnectorPolicy) { p.ManagedHooksOnly = mode })
		if _, err := (codexTarget{}).Reconcile(opts); err != nil {
			t.Fatal(err)
		}
		data := readFile(t, codexPath(t, opts))
		if !strings.Contains(data, "[features]") || !strings.Contains(data, "hooks = true") {
			t.Fatalf("%s: features.hooks must be pinned:\n%s", mode, data)
		}
		if got := strings.Contains(data, "allow_managed_hooks_only = true"); got != (mode == config.ManagedHooksOnlyEnforce) {
			t.Fatalf("%s: lock line present = %v:\n%s", mode, got, data)
		}
	}
}

func TestClaudeReportsBareModeResidual(t *testing.T) {
	state, err := claudeTarget{}.Reconcile(testOptions(t))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, detail := range state.Details {
		found = found || strings.Contains(detail, "--bare")
	}
	if !found {
		t.Fatalf("the --bare residual must be surfaced: %+v", state.Details)
	}
}

const foreignClaudeSettings = `{"hooks": {"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "./rewrite.sh"}]}]}}`

func TestGuardScansClaudeFormatFilesOtherAgentsLoad(t *testing.T) {
	cursor := guardRequest(t, "cursor", config.ForeignHooksRemove)
	writeFile(t, filepath.Join(cursor.Home, ".claude", "settings.json"), foreignClaudeSettings)
	if decision := EvaluateForeignHooks(cursor); !decision.Deny || decision.Findings[0].Scope != ScopeUser {
		t.Fatalf("cursor loads ~/.claude/settings.json: %+v", decision)
	}

	copilot := guardRequest(t, "copilot", config.ForeignHooksRemove)
	writeFile(t, filepath.Join(copilot.Home, ".claude", "settings.json"), foreignClaudeSettings)
	if decision := EvaluateForeignHooks(copilot); decision.Deny || len(decision.Findings) != 0 {
		t.Fatalf("copilot does not load the user Claude settings: %+v", decision)
	}
	writeFile(t, filepath.Join(copilot.WorkingDir, "..", ".claude", "settings.local.json"), foreignClaudeSettings)
	if decision := EvaluateForeignHooks(copilot); !decision.Deny || decision.Findings[0].Scope != ScopeProject {
		t.Fatalf("copilot loads project Claude settings: %+v", decision)
	}

	devin := guardRequest(t, "devin", config.ForeignHooksRemove)
	writeFile(t, filepath.Join(devin.WorkingDir, "..", ".devin", "hooks.v1.json"), `{"PreToolUse": [{"matcher": "*", "hooks": [{"type": "command", "command": "./x.sh"}]}]}`)
	if decision := EvaluateForeignHooks(devin); !decision.Deny {
		t.Fatalf("devin hooks.v1.json is a bare hooks object: %+v", decision)
	}
}

func TestCopilotUntrustedDropInIsAConflict(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix ownership rule")
	}
	opts := testOptions(t)
	opts.SkipTrustChecks = false
	previous := trustedOwner
	uid := uint32(os.Getuid())
	trustedOwner = func(owner uint32) bool { return owner == uid }
	t.Cleanup(func() { trustedOwner = previous })
	if err := os.Chmod(opts.Root, 0o755); err != nil {
		t.Fatal(err)
	}
	state, err := copilotTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	mustNoConflicts(t, state)
	path, _ := copilotDropInPath(opts)
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("drop-in must be written 0644: %v %v", info, err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	state, err = copilotTarget{}.Verify(opts)
	if err != nil {
		t.Fatal(err)
	}
	if state.Covered || !hasConflict(state, "Copilot silently ignores") {
		t.Fatalf("a world-writable drop-in is ignored by Copilot and must not count: %+v", state)
	}
	// Reconcile replaces DefenseClaw's own drop-in when it is untrusted
	// instead of failing every pass.
	state, err = copilotTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatalf("reconcile must repair an untrusted DefenseClaw drop-in: %v", err)
	}
	mustNoConflicts(t, state)
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o644 || !state.Covered {
		t.Fatalf("repaired drop-in: %v %v %+v", info, err, state)
	}
}

func TestOpenCodeManagedPluginRoute(t *testing.T) {
	opts := testOptions(t)
	if route := opts.Route("opencode"); route != RoutePerUser {
		t.Fatalf("without an artifact OpenCode stays per-user, got %s", route)
	}
	opts.OpenCodePluginPath = testOpenCodePlugin
	if route := opts.Route("opencode"); route != RoutePerUser {
		t.Fatalf("a configured but missing artifact must stay per-user, got %s", route)
	}
	installTestOpenCodePlugin(t, &opts)
	if route := opts.Route("opencode"); route != RouteMachinePolicy {
		t.Fatalf("with an artifact OpenCode uses machine policy, got %s", route)
	}
	configPath, _ := OpenCodeManagedConfigPath(opts)
	admin := "{\n  \"$schema\": \"https://opencode.ai/config.json\",\n  \"plugin\": [\"company-audit\"],\n  \"share\": \"disabled\"\n}\n"
	writeFile(t, configPath, admin)

	state, err := opencodeTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	mustNoConflicts(t, state)
	if !state.Covered || state.ForeignEntries != 1 || !state.Changed {
		t.Fatalf("state: %+v", state)
	}
	merged := readFile(t, configPath)
	if !strings.Contains(merged, `"company-audit",`) || !strings.Contains(merged, opts.OpenCodePluginPath) || strings.Index(merged, "$schema") > strings.Index(merged, "plugin") {
		t.Fatalf("merge must keep the administrator's keys and order:\n%s", merged)
	}
	again, err := opencodeTarget{}.Reconcile(opts)
	if err != nil || again.Changed {
		t.Fatalf("reconcile must be idempotent: %+v %v", again, err)
	}
	if _, err := (opencodeTarget{}).RemoveOwned(opts); err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, configPath); got != admin {
		t.Fatalf("removal must restore the preimage exactly:\n%s", got)
	}

	jsonc := filepath.Join(filepath.Dir(configPath), "opencode.jsonc")
	writeFile(t, jsonc, "{\n  // company policy\n  \"plugin\": []\n}\n")
	state, err = opencodeTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	if state.Covered || !hasConflict(state, "verify_only") {
		t.Fatalf("a commented .jsonc cannot be merged: %+v", state)
	}
	if got := readFile(t, jsonc); !strings.Contains(got, "// company policy") {
		t.Fatalf("commented config must stay untouched:\n%s", got)
	}
}

func TestOpenCodeManagedPluginPathLayout(t *testing.T) {
	unix, _ := managed.StandaloneLayoutFor("linux")
	if got := OpenCodeManagedPluginPath(unix); got != "/opt/defenseclaw/share/opencode/defenseclaw.js" {
		t.Fatalf("linux = %q", got)
	}
	windows, _ := managed.StandaloneWindowsLayoutForRoots(`C:\Program Files`, `C:\ProgramData`)
	if got := OpenCodeManagedPluginPath(windows); got != `C:\Program Files\Cisco\DefenseClaw\share\opencode\defenseclaw.js` {
		t.Fatalf("windows = %q", got)
	}
	opts := Options{GOOS: "windows", HookBinary: `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`, WindowsProgramFiles: `C:\Program Files`, WindowsProgramData: `C:\ProgramData`}
	if path, _ := OpenCodeManagedConfigPath(opts); path != `C:\ProgramData\opencode\opencode.json` {
		t.Fatalf("windows config = %q", path)
	}
}
