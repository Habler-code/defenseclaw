// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const foreignHookStopReason = ForeignHookBlockedReasonPrefix + " Earlier in this agent session DefenseClaw found the project file /repo/.claude/settings.local.json. Restart the agent."

// runForeignHookBlocked runs a foreign-hook guard block for one event and
// returns the result and the managed hook failure log.
func runForeignHookBlocked(t *testing.T, connector, event, payload string) (runResult, string) {
	t.Helper()
	var home string
	rt := ok(`{"action":"allow"}`)
	r := run(t, connector, rt, func(o *Options) {
		o.ManagedEnterprise = true
		o.ManagedRuntimeFailure = foreignHookStopReason
		o.Event = event
		if payload != "" {
			o.Stdin = strings.NewReader(payload)
		}
		home = o.Home
	})
	if rt.requests != 0 {
		t.Fatalf("%s %s: a foreign-hook block must not contact the gateway", connector, event+payload)
	}
	log, err := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
	if err != nil {
		t.Fatalf("%s %s: the block must be logged: %v", connector, event+payload, err)
	}
	return r, string(log)
}

// A block on a stop event does not deny anything, it keeps the agent going:
// Claude Code, Codex, Devin and Copilot continue when a stop hook blocks, and
// Cursor submits a stop hook's followup_message as the next prompt. A session
// the guard blocks would loop until the agent restarts. Stop and session-end
// events get the connector's neutral allow; the block is still logged.
func TestForeignHookBlockAllowsStopAndSessionEndEvents(t *testing.T) {
	for _, tc := range []struct {
		connector, event, payload string
		stdout                    string
	}{
		{connector: "claudecode", payload: `{"hook_event_name":"Stop"}`},
		{connector: "claudecode", payload: `{"hook_event_name":"SubagentStop"}`},
		{connector: "claudecode", payload: `{"hook_event_name":"TeammateIdle"}`},
		{connector: "claudecode", payload: `{"hook_event_name":"StopFailure"}`},
		{connector: "claudecode", payload: `{"hook_event_name":"SessionEnd"}`},
		{connector: "codex", event: "Stop"},
		{connector: "codex", event: "SubagentStop"},
		{connector: "codex", event: "SessionEnd"},
		{connector: "cursor", payload: `{"hook_event_name":"stop"}`, stdout: `{}`},
		{connector: "cursor", payload: `{"hook_event_name":"subagentStop"}`, stdout: `{}`},
		{connector: "cursor", payload: `{"hook_event_name":"sessionEnd"}`, stdout: `{}`},
		{connector: "devin", payload: `{"hook_event_name":"Stop"}`},
		{connector: "devin", payload: `{"hook_event_name":"SessionEnd"}`},
		{connector: "copilot", event: "agentStop"},
		{connector: "copilot", event: "subagentStop"},
		{connector: "copilot", event: "sessionEnd"},
	} {
		name := tc.connector + " " + tc.event + tc.payload
		r, log := runForeignHookBlocked(t, tc.connector, tc.event, tc.payload)
		if r.code != 0 || strings.TrimSpace(r.stdout) != tc.stdout {
			t.Fatalf("%s: a stop or session-end event must get the neutral allow %q: code=%d stdout=%q stderr=%q", name, tc.stdout, r.code, r.stdout, r.stderr)
		}
		if !strings.Contains(log, "enterprise_foreign_hook_blocked") || !strings.Contains(log, `"category":"policy"`) || !strings.Contains(log, `"fail_mode":"open"`) {
			t.Fatalf("%s: the block must still be logged, with the allow it got: %s", name, log)
		}
		if !strings.Contains(r.stderr, "/repo/.claude/settings.local.json") {
			t.Fatalf("%s: stderr must still carry the reason: %q", name, r.stderr)
		}
	}
}

// Tool, prompt and session-start events keep the connector's native block.
func TestForeignHookBlockStillDeniesToolPromptAndSessionStartEvents(t *testing.T) {
	for _, tc := range []struct {
		connector, event, payload string
		code                      int
		stdout                    string
	}{
		{connector: "claudecode", payload: `{"hook_event_name":"PreToolUse"}`, code: 2},
		{connector: "claudecode", payload: `{"hook_event_name":"UserPromptSubmit"}`, code: 2},
		{connector: "claudecode", payload: `{"hook_event_name":"SessionStart"}`, code: 2},
		{connector: "codex", event: "PreToolUse", stdout: `"permissionDecision":"deny"`},
		{connector: "codex", event: "UserPromptSubmit", stdout: `"decision":"block"`},
		{connector: "codex", event: "SessionStart", stdout: `"continue":false`},
		{connector: "cursor", payload: `{"hook_event_name":"preToolUse"}`, code: 2, stdout: `"permission":"deny"`},
		{connector: "cursor", payload: `{"hook_event_name":"beforeSubmitPrompt"}`, code: 2, stdout: `"continue":false`},
		{connector: "cursor", payload: `{"hook_event_name":"sessionStart"}`, code: 2, stdout: `{}`},
		{connector: "devin", payload: `{"hook_event_name":"PreToolUse"}`, code: 2, stdout: `"decision":"block"`},
		{connector: "devin", payload: `{"hook_event_name":"UserPromptSubmit"}`, code: 2, stdout: `"decision":"block"`},
		{connector: "devin", payload: `{"hook_event_name":"SessionStart"}`, code: 2, stdout: `"decision":"block"`},
		{connector: "copilot", event: "preToolUse", stdout: `"permissionDecision":"deny"`},
		{connector: "copilot", event: "permissionRequest", stdout: `"behavior":"deny"`},
		// A payload that names no event is not a stop event.
		{connector: "claudecode", payload: `{}`, code: 2},
		{connector: "devin", payload: `{"hook_event_name":"Stop","event":"PreToolUse"}`, code: 2, stdout: `"decision":"block"`},
	} {
		name := tc.connector + " " + tc.event + tc.payload
		r, log := runForeignHookBlocked(t, tc.connector, tc.event, tc.payload)
		if r.code != tc.code || !strings.Contains(r.stdout, tc.stdout) {
			t.Fatalf("%s: the event must stay blocked: code=%d stdout=%q stderr=%q", name, r.code, r.stdout, r.stderr)
		}
		if tc.stdout == "" && strings.TrimSpace(r.stdout) != "" {
			t.Fatalf("%s: unexpected stdout %q", name, r.stdout)
		}
		if !strings.Contains(log, `"fail_mode":"closed"`) {
			t.Fatalf("%s: the block must be logged as closed: %s", name, log)
		}
	}
}
