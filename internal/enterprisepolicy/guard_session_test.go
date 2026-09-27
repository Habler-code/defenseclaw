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
	// At a session start with unknown process, the session is reset and
	// the current scan is trusted (the agent loaded hooks from current files).
	h.process = ""
	if start := h.apply("s-1", true, GuardDecision{}); start.Deny {
		t.Fatalf("session start with unknown process must trust current scan: %+v", start)
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

func TestGatewaySessionStateDeniesWhenRecordCannotBeWrittenOrRead(t *testing.T) {
	root := t.TempDir()
	blockedParent := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(blockedParent, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	update := SessionUpdate{
		StateDir: filepath.Join(blockedParent, "records"),
		Key:      SessionKey{Connector: "claudecode", Session: "s-1"},
		Decision: GuardDecision{},
	}
	if decision := ApplyForeignHookSession(update); !decision.Deny || !strings.Contains(decision.Reason, "cannot verify") {
		t.Fatalf("unwritable gateway record must deny: %+v", decision)
	}

	update.StateDir = filepath.Join(root, "records")
	if err := os.MkdirAll(update.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := sessionPathInDir(update.StateDir, "claudecode", sessionKindSession, "s-1")
	if err := os.WriteFile(path, []byte("{bad"), 0o600); err != nil {
		t.Fatal(err)
	}
	if decision := ApplyForeignHookSession(update); !decision.Deny || !strings.Contains(decision.Reason, "cannot verify") {
		t.Fatalf("unreadable gateway record must deny: %+v", decision)
	}
	if err := os.WriteFile(path, []byte(`{"v":1,"connector":"claudecode","session":"s-1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if decision := ApplyForeignHookSession(update); !decision.Deny || !strings.Contains(decision.Reason, "cannot verify") {
		t.Fatalf("incomplete gateway record must deny: %+v", decision)
	}
}

// A hook file DefenseClaw cannot read or parse denies the call, but it is
// not a foreign hook: no session block is recorded, and once the file reads
// cleanly the next call of the same session is allowed.
func TestSessionStateFileErrorsDoNotBlock(t *testing.T) {
	h := newSessionHarness(t)
	h.process = runtime.GOOS + "::111:1"
	unreadable := GuardDecision{
		Deny:   true,
		Reason: "enterprise_foreign_hook_blocked: the project file /r/.claude/settings.json cannot be verified",
		Findings: []Finding{{
			Connector: "claudecode",
			Scope:     ScopeProject,
			Path:      "/r/.claude/settings.json",
			Digest:    "unverifiable",
			Reason:    "cannot verify hook file: file truncated",
		}},
	}
	if result := h.apply("s-1", true, unreadable); !result.Deny {
		t.Fatalf("an unreadable hook file must deny the call: %+v", result)
	}
	record, exists, err := readSessionRecord(SessionPath(h.home, "claudecode", sessionKindSession, "s-1"))
	if err != nil || !exists {
		t.Fatalf("the session snapshot must be recorded at session start: exists=%v err=%v", exists, err)
	}
	if record.Blocked {
		t.Fatalf("an unreadable file must not block the session: %+v", record)
	}
	if later := h.apply("s-1", false, GuardDecision{}); later.Deny {
		t.Fatalf("once the file reads cleanly the session must be allowed: %+v", later)
	}
}

// An unapproved plugin names no event, and still blocks the session (OpenCode
// and Amp load plugins once per process).
func TestSessionStateBlocksForAnUnapprovedPlugin(t *testing.T) {
	h := newSessionHarness(t)
	h.process = runtime.GOOS + "::121:1"
	plugin := GuardDecision{
		Deny:     true,
		Reason:   "enterprise_foreign_hook_blocked: the project file /r/.opencode/plugins/x.js added a plugin.",
		Findings: []Finding{{Connector: "claudecode", Scope: ScopeProject, Path: "/r/.opencode/plugins/x.js", Digest: "dd44", Reason: "plugin"}},
	}
	h.apply("s-1", true, plugin)
	if record := h.record(sessionKindProcess, h.process); !record.Blocked || record.Reason != "plugin" {
		t.Fatalf("an unapproved plugin must block the agent process: %+v", record)
	}
	if later := h.apply("s-1", false, GuardDecision{}); !later.Deny || !strings.Contains(later.Reason, "added a plugin") {
		t.Fatalf("the process that loaded the plugin must stay blocked: %+v", later)
	}
}

// A session start whose agent process cannot be named resets the session:
// the agent loaded its hooks from the files DefenseClaw just checked.
func TestSessionStateResetsAtSessionStartWithUnknownProcess(t *testing.T) {
	h := newSessionHarness(t)
	h.process = runtime.GOOS + "::222:2"
	h.apply("s-1", true, sessionDeny("/r/.claude/hooks.json", "bb22"))
	h.process = ""
	if result := h.apply("s-1", true, GuardDecision{}); result.Deny {
		t.Fatalf("a session start without a process identity must trust the current scan: %+v", result)
	}
	if record := h.record(sessionKindSession, "s-1"); record.Blocked {
		t.Fatalf("the session record must be reset at the session start: %+v", record)
	}
}

// Repeated denials of a blocked session keep the time of the block.
func TestSessionStateBlockedAtDoesNotChangeOnRepeatedDenials(t *testing.T) {
	h := newSessionHarness(t)
	h.process = runtime.GOOS + "::333:3"
	h.apply("s-1", true, sessionDeny("/r/.claude/hooks.json", "cc33"))
	blockedAt := h.record(sessionKindSession, "s-1").BlockedAt
	if blockedAt == "" {
		t.Fatal("a blocked session must record when it was blocked")
	}
	for i := 0; i < 20; i++ {
		h.now = h.now.Add(6 * time.Hour)
		h.apply("s-1", false, GuardDecision{})
	}
	if later := h.record(sessionKindSession, "s-1").BlockedAt; later != blockedAt {
		t.Fatalf("repeated denials must keep the block time: was %s, now %s", blockedAt, later)
	}
}
