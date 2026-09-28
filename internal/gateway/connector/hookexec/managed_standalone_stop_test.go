// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// managedStandaloneFailure is one way a Unix standalone managed hook fails
// closed without a gateway verdict.
type managedStandaloneFailure struct {
	name   string
	rt     func() *stubRT
	mutate func(*Options)
}

var managedStandaloneFailures = []managedStandaloneFailure{
	{
		// The descriptor names no hook socket: the CLI hands hookexec the
		// runtime failure and marks it as the standalone profile's.
		name: "hook socket missing",
		rt:   func() *stubRT { return ok(`{"action":"allow"}`) },
		mutate: func(o *Options) {
			o.ManagedRuntimeFailure = "enterprise_managed_hook_socket_missing"
		},
	},
	{
		name: "empty ManagedUnixSocket",
		rt:   func() *stubRT { return ok(`{"action":"allow"}`) },
		mutate: func(o *Options) {
			o.ManagedUnixSocket = ""
		},
	},
	{
		name: "transport error",
		rt:   func() *stubRT { return &stubRT{err: errors.New("dial unix: connection refused")} },
		mutate: func(o *Options) {
			o.ManagedUnixSocket = "/run/defenseclaw-hook/hook.sock"
		},
	},
	{
		name: "unusable gateway response",
		rt:   func() *stubRT { return ok("not json") },
		mutate: func(o *Options) {
			o.ManagedUnixSocket = "/run/defenseclaw-hook/hook.sock"
		},
	},
}

type managedStandaloneEvent struct {
	connector, event, payload string
}

// managedStandaloneRun runs one managed standalone hook that fails closed.
func managedStandaloneRun(t *testing.T, failure managedStandaloneFailure, ev managedStandaloneEvent, standalone bool) (runResult, string) {
	t.Helper()
	var home string
	rt := failure.rt()
	r := run(t, ev.connector, rt, func(o *Options) {
		o.ManagedEnterprise = true
		o.ManagedStandalone = standalone
		o.FailMode = "closed"
		o.StrictAvailability = true
		o.ManagedServiceUID = 0
		o.Event = ev.event
		if ev.payload != "" {
			o.Stdin = strings.NewReader(ev.payload)
		} else if ev.connector == "codex" {
			o.Stdin = strings.NewReader(`{"hook_event_name":"` + ev.event + `"}`)
		}
		failure.mutate(o)
		home = o.Home
	})
	log, _ := os.ReadFile(filepath.Join(home, "logs", "hook-failures.jsonl"))
	return r, string(log)
}

// On the standalone profile a stop event that fails closed would keep the
// agent running (Claude Code, Codex and Devin continue the turn, Cursor
// submits the followup message), so an outage loops every turn. Every
// fail-closed reason gives stop events the connector's neutral allow and
// logs it as fail mode open.
func TestManagedStandaloneFailClosedAllowsStopEvents(t *testing.T) {
	stops := []struct {
		managedStandaloneEvent
		stdout string
	}{
		{managedStandaloneEvent{connector: "claudecode", payload: `{"hook_event_name":"Stop","stop_hook_active":false}`}, ""},
		{managedStandaloneEvent{connector: "claudecode", payload: `{"hook_event_name":"SubagentStop"}`}, ""},
		{managedStandaloneEvent{connector: "claudecode", payload: `{"hook_event_name":"TeammateIdle"}`}, ""},
		{managedStandaloneEvent{connector: "codex", event: "Stop"}, ""},
		{managedStandaloneEvent{connector: "codex", event: "SubagentStop"}, ""},
		{managedStandaloneEvent{connector: "devin", payload: `{"hook_event_name":"Stop"}`}, ""},
		{managedStandaloneEvent{connector: "cursor", payload: `{"hook_event_name":"stop"}`}, "{}"},
		{managedStandaloneEvent{connector: "cursor", payload: `{"hook_event_name":"subagentStop"}`}, "{}"},
	}
	for _, failure := range managedStandaloneFailures {
		for _, tc := range stops {
			name := failure.name + ": " + tc.connector + " " + tc.event + tc.payload
			r, log := managedStandaloneRun(t, failure, tc.managedStandaloneEvent, true)
			if r.code != 0 || strings.TrimSpace(r.stdout) != tc.stdout {
				t.Fatalf("%s: want the neutral allow %q, got code=%d stdout=%q stderr=%q", name, tc.stdout, r.code, r.stdout, r.stderr)
			}
			if !strings.Contains(log, `"fail_mode":"open"`) {
				t.Fatalf("%s: the failure must be logged with the allow it got: %s", name, log)
			}
			if !strings.HasPrefix(r.stderr, "DefenseClaw is not blocking the ") {
				t.Fatalf("%s: stderr = %q", name, r.stderr)
			}
		}
	}
}

// Prompt and tool events keep failing closed on the standalone profile.
func TestManagedStandaloneFailClosedStillBlocksPromptAndToolEvents(t *testing.T) {
	blocked := []struct {
		managedStandaloneEvent
		code   int
		stdout string
	}{
		{managedStandaloneEvent{connector: "claudecode", payload: `{"hook_event_name":"PreToolUse"}`}, 2, ""},
		{managedStandaloneEvent{connector: "claudecode", payload: `{"hook_event_name":"UserPromptSubmit"}`}, 2, ""},
		{managedStandaloneEvent{connector: "codex", event: "PreToolUse"}, 0, `"permissionDecision":"deny"`},
		{managedStandaloneEvent{connector: "devin", payload: `{"hook_event_name":"PreToolUse"}`}, 2, `"decision":"block"`},
		// Cursor's response-layer deny exits 0; the body carries it.
		{managedStandaloneEvent{connector: "cursor", payload: `{"hook_event_name":"preToolUse"}`}, -1, `"permission":"deny"`},
		// A payload that names no event is not a stop event.
		{managedStandaloneEvent{connector: "claudecode", payload: `{}`}, 2, ""},
	}
	for _, failure := range managedStandaloneFailures {
		for _, tc := range blocked {
			name := failure.name + ": " + tc.connector + " " + tc.event + tc.payload
			r, _ := managedStandaloneRun(t, failure, tc.managedStandaloneEvent, true)
			if (tc.code >= 0 && r.code != tc.code) || !strings.Contains(r.stdout, tc.stdout) {
				t.Fatalf("%s: want a block, got code=%d stdout=%q stderr=%q", name, r.code, r.stdout, r.stderr)
			}
		}
	}
}

// Outside the standalone profile (the Secure Client profile and every other
// managed hook) a stop event keeps its fail-closed result.
func TestManagedFailClosedStopOutsideStandaloneIsUnchanged(t *testing.T) {
	failure := managedStandaloneFailures[0]
	for _, tc := range []struct {
		managedStandaloneEvent
		code   int
		stdout string
	}{
		{managedStandaloneEvent{connector: "claudecode", payload: `{"hook_event_name":"Stop"}`}, 2, ""},
		{managedStandaloneEvent{connector: "codex", event: "Stop"}, 0, `{"decision":"block","reason":"DefenseClaw hook failed closed"}`},
		{managedStandaloneEvent{connector: "devin", payload: `{"hook_event_name":"Stop"}`}, 2, `{"decision":"block","reason":"DefenseClaw hook failed closed"}`},
		// The runtime failure never reads Cursor's payload there: the event
		// stays unnamed, so Cursor gets exit 2 and an empty body.
		{managedStandaloneEvent{connector: "cursor", payload: `{"hook_event_name":"stop"}`}, 2, `{}`},
	} {
		name := tc.connector + " " + tc.event + tc.payload
		r, _ := managedStandaloneRun(t, failure, tc.managedStandaloneEvent, false)
		if r.code != tc.code || strings.TrimSpace(r.stdout) != tc.stdout {
			t.Fatalf("%s: want the unchanged fail-closed result, got code=%d stdout=%q stderr=%q", name, r.code, r.stdout, r.stderr)
		}
	}
}
