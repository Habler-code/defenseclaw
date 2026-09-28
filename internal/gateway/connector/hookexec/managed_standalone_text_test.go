// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"strings"
	"testing"
)

// A Unix standalone managed hook that fails closed says, in one line that
// starts with DefenseClaw, what it blocked (a prompt is not a tool call),
// why and what to do, with the internal reason code last in parentheses.
// Claude Code shows this stderr line as the block message; Codex, Devin and
// Cursor show the reason in their block body.
func TestManagedStandaloneFailClosedTextIsPlain(t *testing.T) {
	const unavailable = "the DefenseClaw gateway is not available. Try again in a moment; if this continues, contact your administrator."
	const notSetUp = "DefenseClaw is not set up correctly on this computer. Contact your administrator."
	for _, tc := range []struct {
		name    string
		failure managedStandaloneFailure
		ev      managedStandaloneEvent
		want    string
		body    bool
	}{
		{
			name:    "claude prompt, gateway unreachable",
			failure: managedStandaloneFailures[2],
			ev:      managedStandaloneEvent{connector: "claudecode", payload: `{"hook_event_name":"UserPromptSubmit"}`},
			want:    "DefenseClaw blocked this prompt: " + unavailable + " (gateway unreachable)",
		},
		{
			name:    "claude prompt, socket not verified",
			failure: managedStandaloneFailures[1],
			ev:      managedStandaloneEvent{connector: "claudecode", payload: `{"hook_event_name":"UserPromptSubmit"}`},
			want:    "DefenseClaw blocked this prompt: " + unavailable + " (enterprise_managed_gateway_peer_unverified)",
		},
		{
			name:    "claude tool call, hook socket missing",
			failure: managedStandaloneFailures[0],
			ev:      managedStandaloneEvent{connector: "claudecode", payload: `{"hook_event_name":"PreToolUse"}`},
			want:    "DefenseClaw blocked this tool call: " + notSetUp + " (enterprise_managed_hook_socket_missing)",
		},
		{
			name:    "codex prompt, gateway unreachable",
			failure: managedStandaloneFailures[2],
			ev:      managedStandaloneEvent{connector: "codex", event: "UserPromptSubmit"},
			want:    "DefenseClaw blocked this prompt: " + unavailable + " (gateway unreachable)",
			body:    true,
		},
		{
			name:    "devin tool call, unusable response",
			failure: managedStandaloneFailures[3],
			ev:      managedStandaloneEvent{connector: "devin", payload: `{"hook_event_name":"PreToolUse"}`},
			want:    "DefenseClaw blocked this tool call: the DefenseClaw gateway returned an answer DefenseClaw could not use. Try again; if this continues, contact your administrator. (invalid JSON response)",
			body:    true,
		},
		{
			name:    "cursor prompt, hook socket missing",
			failure: managedStandaloneFailures[0],
			ev:      managedStandaloneEvent{connector: "cursor", payload: `{"hook_event_name":"beforeSubmitPrompt"}`},
			want:    "DefenseClaw blocked this prompt: " + notSetUp + " (enterprise_managed_hook_socket_missing)",
			body:    true,
		},
	} {
		r, _ := managedStandaloneRun(t, tc.failure, tc.ev, true)
		if got := strings.TrimSpace(r.stderr); got != tc.want {
			t.Fatalf("%s: stderr\n got %q\nwant %q", tc.name, got, tc.want)
		}
		if tc.body && !strings.Contains(r.stdout, mustJSONString(tc.want)) {
			t.Fatalf("%s: block body must carry the same text: %q", tc.name, r.stdout)
		}
		if strings.Contains(r.stderr, "claude-code tool") || strings.Contains(r.stderr, "token drift") {
			t.Fatalf("%s: internal wording leaked: %q", tc.name, r.stderr)
		}
	}
}

// Outside the standalone profile (Secure Client and every other managed
// hook) the fail-closed text is unchanged.
func TestManagedFailClosedTextOutsideStandaloneIsUnchanged(t *testing.T) {
	r, _ := managedStandaloneRun(t, managedStandaloneFailures[0],
		managedStandaloneEvent{connector: "claudecode", payload: `{"hook_event_name":"UserPromptSubmit"}`}, false)
	if want := "defenseclaw: gateway unreachable, blocking claude-code tool (fail mode closed): enterprise_managed_hook_socket_missing"; strings.TrimSpace(r.stderr) != want {
		t.Fatalf("stderr = %q, want %q", r.stderr, want)
	}
	r, _ = managedStandaloneRun(t, managedStandaloneFailures[0],
		managedStandaloneEvent{connector: "codex", event: "UserPromptSubmit"}, false)
	if want := `{"decision":"block","reason":"DefenseClaw hook failed closed"}`; strings.TrimSpace(r.stdout) != want {
		t.Fatalf("stdout = %q, want %q", r.stdout, want)
	}
}

func TestHookEventSubject(t *testing.T) {
	for event, want := range map[string]string{
		"UserPromptSubmit":    "prompt",
		"beforeSubmitPrompt":  "prompt",
		"userPromptSubmitted": "prompt",
		"PreToolUse":          "tool call",
		"PermissionRequest":   "tool call",
		"preToolUse":          "tool call",
		"tool.execute.before": "tool call",
		"PostToolUse":         "tool result",
		"SessionStart":        "session start",
		"PreCompact":          "PreCompact event",
		"":                    "request",
	} {
		if got := hookEventSubject(event); got != want {
			t.Fatalf("hookEventSubject(%q) = %q, want %q", event, got, want)
		}
	}
}
