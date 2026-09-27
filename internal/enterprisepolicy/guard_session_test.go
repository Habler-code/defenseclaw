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
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func sessionDeny(path, digest string) GuardDecision {
	return GuardDecision{
		Deny:     true,
		Reason:   "enterprise_foreign_hook_blocked: the project file " + path + " defines a hook.",
		Findings: []Finding{{Connector: "claudecode", Scope: ScopeProject, Path: path, Event: "PreToolUse", Digest: digest}},
	}
}

type sessionHarness struct {
	t       *testing.T
	home    string
	now     time.Time
	process string
}

func newSessionHarness(t *testing.T) *sessionHarness {
	return &sessionHarness{t: t, home: t.TempDir(), now: time.Date(2026, 9, 27, 12, 0, 0, 0, time.UTC)}
}

func (h *sessionHarness) apply(session string, start bool, decision GuardDecision) GuardDecision {
	h.t.Helper()
	h.now = h.now.Add(time.Second)
	return ApplyForeignHookSession(SessionUpdate{
		AccountHome:  h.home,
		Key:          SessionKey{Connector: "claudecode", Session: session, Process: h.process},
		SessionStart: start,
		Decision:     decision,
		Now:          h.now,
	})
}

func (h *sessionHarness) record(kind, id string) SessionRecord {
	h.t.Helper()
	data, err := os.ReadFile(SessionPath(h.home, "claudecode", kind, id))
	if err != nil {
		h.t.Fatalf("read %s record %q: %v", kind, id, err)
	}
	var record SessionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		h.t.Fatal(err)
	}
	return record
}

// A session that started with a foreign hook keeps being denied after the
// file is cleaned: the agent still runs the hook it loaded at start.
func TestSessionStateKeepsDenyingASessionAfterTheHookIsRemoved(t *testing.T) {
	h := newSessionHarness(t)
	hookFile := "/work/repo/.claude/settings.local.json"
	first := h.apply("s-1", true, sessionDeny(hookFile, "aa11"))
	if !first.Deny || !strings.Contains(first.Reason, "restart the agent") || !strings.Contains(first.Reason, hookFile) {
		t.Fatalf("the session-start denial must name the file and say to restart the agent: %+v", first)
	}
	record := h.record(sessionKindSession, "s-1")
	if !record.Blocked || record.Path != hookFile || record.Digest != "aa11" || record.State != ForeignHookStateHash(first.Findings) {
		t.Fatalf("the session snapshot must record the block and the state hash: %+v", record)
	}

	later := h.apply("s-1", false, GuardDecision{})
	if !later.Deny || !strings.HasPrefix(later.Reason, "enterprise_foreign_hook_blocked:") {
		t.Fatalf("a clean scan later in the session must still deny: %+v", later)
	}
	for _, want := range []string{"Earlier in this agent session", hookFile, "sha256:aa11", "restart the agent"} {
		if !strings.Contains(later.Reason, want) {
			t.Fatalf("the session denial must say %q: %s", want, later.Reason)
		}
	}
	if len(later.Findings) == 0 || later.Findings[0].Allowed || later.Findings[0].Path != hookFile {
		t.Fatalf("the session denial carries the recorded finding for the block record: %+v", later.Findings)
	}
	if other := h.apply("s-2", false, GuardDecision{}); other.Deny {
		t.Fatalf("another session with no recorded block and no shared process is not affected: %+v", other)
	}
}

// The process key carries the block into sessions the same agent process
// runs later (a cleared, compacted or resumed session). A restarted agent
// resuming the session starts clean, while the old process stays blocked.
func TestSessionStateFollowsTheAgentProcess(t *testing.T) {
	h := newSessionHarness(t)
	oldProcess := runtime.GOOS + "::4242:100"
	h.process = oldProcess
	h.apply("s-1", true, sessionDeny("/r/.claude/settings.json", "bb22"))
	if cleared := h.apply("s-2", true, GuardDecision{}); !cleared.Deny || !strings.Contains(cleared.Reason, "/r/.claude/settings.json") {
		t.Fatalf("a new session of the same agent process keeps the block: %+v", cleared)
	}
	if !h.record(sessionKindSession, "s-2").Blocked {
		t.Fatal("the block must be carried to the new session's record")
	}
	if resumed := h.apply("s-1", true, GuardDecision{}); !resumed.Deny {
		t.Fatalf("the same process resuming the session keeps the block: %+v", resumed)
	}

	// A restarted agent loaded its hooks from the clean files.
	h.process = runtime.GOOS + "::6262:300"
	if resumed := h.apply("s-2", true, GuardDecision{}); resumed.Deny {
		t.Fatalf("a restarted agent resuming the session must start clean: %+v", resumed)
	}
	if record := h.record(sessionKindSession, "s-2"); record.Blocked || record.Process != h.process {
		t.Fatalf("the resumed session's record must be the new process's clean snapshot: %+v", record)
	}
	if later := h.apply("s-2", false, GuardDecision{}); later.Deny {
		t.Fatalf("the resumed session stays clean: %+v", later)
	}
	// The old process may still run (a second terminal): it stays blocked,
	// without blocking the restarted agent's session.
	restarted := h.process
	h.process = oldProcess
	if call := h.apply("s-2", false, GuardDecision{}); !call.Deny {
		t.Fatalf("the process that loaded the hook stays blocked: %+v", call)
	}
	h.process = restarted
	if later := h.apply("s-2", false, GuardDecision{}); later.Deny {
		t.Fatalf("the old process must not block the restarted agent's session: %+v", later)
	}

	// Only a session start resets: a tool call of the old session in a new
	// process still denies.
	h.process = runtime.GOOS + "::7373:400"
	if call := h.apply("s-1", false, GuardDecision{}); !call.Deny {
		t.Fatalf("a blocked session is reset only at a session start: %+v", call)
	}
	// And a session start whose process cannot be named keeps the block.
	h.process = ""
	if start := h.apply("s-1", true, GuardDecision{}); !start.Deny {
		t.Fatalf("without a process identity the session record holds: %+v", start)
	}
}

// With no session ID in the payload the process key alone holds the block.
func TestSessionStateUsesTheProcessWithoutASessionID(t *testing.T) {
	h := newSessionHarness(t)
	h.process = runtime.GOOS + "::99:1"
	h.apply("", false, sessionDeny("/r/.github/hooks/x.json", "cc33"))
	if later := h.apply("", false, GuardDecision{}); !later.Deny {
		t.Fatalf("the agent process keeps the block: %+v", later)
	}
	h.process = ""
	if unknown := h.apply("", false, GuardDecision{}); unknown.Deny {
		t.Fatalf("with neither key the scan alone decides: %+v", unknown)
	}
}

// A clean session start records its snapshot; an allowed hook present at
// start is part of the state hash.
func TestSessionStateRecordsTheSnapshotAtSessionStart(t *testing.T) {
	h := newSessionHarness(t)
	h.process = runtime.GOOS + "::11:1"
	if decision := h.apply("s-1", true, GuardDecision{}); decision.Deny {
		t.Fatalf("a clean start allows: %+v", decision)
	}
	clean := h.record(sessionKindSession, "s-1")
	if clean.Blocked || clean.State != ForeignHookStateHash(nil) || clean.Started == "" || clean.Process != h.process {
		t.Fatalf("clean snapshot: %+v", clean)
	}
	if process := h.record(sessionKindProcess, h.process); process.Blocked || process.Session != "s-1" {
		t.Fatalf("process snapshot: %+v", process)
	}
	approved := GuardDecision{Findings: []Finding{{Connector: "claudecode", Scope: ScopeProject, Path: "/r/x.json", Digest: "dd44", Allowed: true}}}
	h.apply("s-2", true, approved)
	if state := h.record(sessionKindSession, "s-2").State; state == ForeignHookStateHash(nil) || state != ForeignHookStateHash(approved.Findings) {
		t.Fatalf("the state hash must cover an approved hook: %q", state)
	}
	// Later calls keep the start snapshot.
	h.apply("s-2", false, GuardDecision{})
	if state := h.record(sessionKindSession, "s-2").State; state != ForeignHookStateHash(approved.Findings) {
		t.Fatalf("a later call must not replace the start snapshot: %q", state)
	}
}

func TestForeignHookStateHashIsOrderIndependent(t *testing.T) {
	a := Finding{Connector: "cursor", Scope: ScopeUser, Path: "/a", Digest: "1"}
	b := Finding{Connector: "cursor", Scope: ScopeProject, Path: "/b", Digest: "2", Allowed: true}
	if ForeignHookStateHash([]Finding{a, b}) != ForeignHookStateHash([]Finding{b, a}) {
		t.Fatal("the hash must not depend on scan order")
	}
	approved := b
	approved.Allowed = false
	if ForeignHookStateHash([]Finding{a, b}) == ForeignHookStateHash([]Finding{a, approved}) {
		t.Fatal("the hash must cover each finding's approval")
	}
	if ForeignHookStateHash(nil) != ForeignHookStateHash([]Finding{}) || !strings.HasPrefix(ForeignHookStateHash(nil), "sha256:") {
		t.Fatal("an empty state has one hash")
	}
}

// A record that exists but cannot be read proves nothing: deny.
func TestSessionStateDeniesOnAnUnreadableRecord(t *testing.T) {
	h := newSessionHarness(t)
	path := SessionPath(h.home, "claudecode", sessionKindSession, "s-1")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if decision := h.apply("s-1", false, GuardDecision{}); !decision.Deny || !strings.Contains(decision.Reason, "could not verify") {
		t.Fatalf("a corrupt record must deny: %+v", decision)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if decision := h.apply("s-1", false, GuardDecision{}); !decision.Deny {
		t.Fatalf("a directory at the record path must deny: %+v", decision)
	}
	if runtime.GOOS != "windows" {
		linked := SessionPath(h.home, "claudecode", sessionKindSession, "s-9")
		target := filepath.Join(h.home, "elsewhere.json")
		if err := os.WriteFile(target, []byte(`{"v":1,"connector":"claudecode","blocked":false}`), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, linked); err != nil {
			t.Fatal(err)
		}
		if decision := h.apply("s-9", false, GuardDecision{}); !decision.Deny {
			t.Fatalf("a linked record must deny: %+v", decision)
		}
		if data, _ := os.ReadFile(target); !strings.Contains(string(data), `"blocked":false`) {
			t.Fatalf("nothing may be written through the link: %s", data)
		}
	}
}

// Records untouched for the retention period are pruned at a session start;
// a blocked record that keeps denying is refreshed and survives.
func TestSessionStatePrunesOldRecords(t *testing.T) {
	h := newSessionHarness(t)
	h.apply("old", true, GuardDecision{})
	h.apply("blocked", true, sessionDeny("/r/x.json", "ee55"))
	old := SessionPath(h.home, "claudecode", sessionKindSession, "old")
	blocked := SessionPath(h.home, "claudecode", sessionKindSession, "blocked")
	stale := h.now.Add(-sessionRecordTTL - time.Hour)
	for _, path := range []string{old, blocked} {
		if err := os.Chtimes(path, stale, stale); err != nil {
			t.Fatal(err)
		}
	}
	if decision := h.apply("blocked", false, GuardDecision{}); !decision.Deny {
		t.Fatalf("the blocked session still denies: %+v", decision)
	}
	h.apply("new", true, GuardDecision{})
	if _, err := os.Stat(old); !os.IsNotExist(err) {
		t.Fatalf("an untouched old record must be pruned: %v", err)
	}
	if _, err := os.Stat(blocked); err != nil {
		t.Fatalf("a blocked record that denied recently must survive: %v", err)
	}
}

func TestSessionStateIgnoresRequestsWithoutAHome(t *testing.T) {
	decision := sessionDeny("/r/x.json", "ff66")
	for _, home := range []string{"", "relative/home"} {
		got := ApplyForeignHookSession(SessionUpdate{AccountHome: home, Key: SessionKey{Connector: "cursor", Session: "s"}, Decision: decision})
		if got.Reason != decision.Reason {
			t.Fatalf("%q: without an absolute home the decision is unchanged: %+v", home, got)
		}
	}
}
