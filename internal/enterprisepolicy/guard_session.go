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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Per-session foreign-hook state.
//
// Claude Code, Codex and Copilot CLI read their hooks when a session starts
// and keep running them for the rest of the session, even after the file
// that defined a hook changes or disappears; OpenCode and Amp load plugins
// once per process. Checking the files on every call therefore misses a
// foreign hook that was present when the session started and was deleted
// afterwards. So the hook records a snapshot at SessionStart (the hash of
// the foreign-hook state it found) and, once a call of a session was denied
// for a foreign hook, keeps denying that session's tool calls until the
// agent restarts.
//
// A snapshot is keyed twice: by the agent's session ID from the hook
// payload, and by the agent process that runs the hook
// (internal/agentprocess). The process key carries the state across the
// sessions one process runs (a cleared, compacted or resumed session keeps
// the hooks the process loaded); the session key covers an agent whose
// process cannot be named. A restarted agent that resumes a session starts
// clean; the process that held the old hooks stays blocked.
//
// The records live in the user's data directory under the account's home,
// next to the block records, and like them are advisory: the user owns
// them. They stop a snapshotted hook from keeping its effect after an edit;
// the guard's other checks do not depend on them.

const (
	sessionDirName = "foreign-hook-sessions"
	// sessionRecordLimit bounds one record.
	sessionRecordLimit = 16 << 10
	// sessionRecordTTL is how long an untouched record is kept. A blocked
	// record is touched whenever it denies a call, so a long-running
	// blocked agent keeps its record.
	sessionRecordTTL = 7 * 24 * time.Hour
	// sessionTouchAfter is how old a blocked record gets before a denial
	// refreshes it.
	sessionTouchAfter = 24 * time.Hour
	// sessionDirLimit bounds the records kept per user.
	sessionDirLimit = 512
	// sessionIDLimit bounds a session ID or process identity.
	sessionIDLimit = 512
)

// SessionKey names one agent session.
type SessionKey struct {
	Connector string
	// Session is the agent's session ID from the hook payload ("" when the
	// payload has none).
	Session string
	// Process is the identity of the agent process running the hook ("" when
	// it cannot be named).
	Process string
}

func (k SessionKey) valid() bool {
	return strings.TrimSpace(k.Connector) != "" && (k.Session != "" || k.Process != "") &&
		len(k.Session) <= sessionIDLimit && len(k.Process) <= sessionIDLimit
}

// SessionRecord is one snapshot.
type SessionRecord struct {
	Version   int    `json:"v"`
	Connector string `json:"connector"`
	Session   string `json:"session,omitempty"`
	Process   string `json:"process,omitempty"`
	// Started is when the snapshot was taken and State the hash of the
	// foreign-hook state then (ForeignHookStateHash).
	Started string `json:"started"`
	State   string `json:"state"`
	// Blocked is set once a call of the session was denied for a foreign
	// hook; Scope, Path, Digest and Reason describe the first unapproved
	// finding of that denial.
	Blocked   bool   `json:"blocked"`
	BlockedAt string `json:"blocked_at,omitempty"`
	Scope     string `json:"scope,omitempty"`
	Path      string `json:"path,omitempty"`
	Digest    string `json:"digest,omitempty"`
	Reason    string `json:"reason,omitempty"`
}

// ForeignHookStateHash hashes the foreign-hook state a scan found: every
// finding's scope, path, event, digest and approval, in a stable order. A
// scan with no findings hashes to the same value every time.
func ForeignHookStateHash(findings []Finding) string {
	lines := make([]string, 0, len(findings))
	for _, finding := range findings {
		lines = append(lines, strings.Join([]string{
			finding.Connector, finding.Scope, finding.Path, finding.Event, finding.Digest, fmt.Sprint(finding.Allowed),
		}, "\x00"))
	}
	sort.Strings(lines)
	return "sha256:" + sha256Hex([]byte(strings.Join(lines, "\n")))
}

// SessionUpdate is one hook invocation's input to the session state.
type SessionUpdate struct {
	// AccountHome is the account's home from the system account database.
	AccountHome string
	Key         SessionKey
	// SessionStart marks the agent's session-start event, where the
	// snapshot is taken.
	SessionStart bool
	// Decision is this invocation's scan result.
	Decision GuardDecision
	Now      time.Time
}

// SessionPath is the record for one key kind and ID under accountHome.
func SessionPath(accountHome, connector, kind, id string) string {
	name := kind + "-" + sha256Hex([]byte(connector + "\x00" + kind + "\x00" + id))[:40] + ".json"
	return filepath.Join(accountHome, ".defenseclaw", sessionDirName, name)
}

const (
	sessionKindProcess = "p"
	sessionKindSession = "s"
)

// ApplyForeignHookSession combines this invocation's scan with the
// session's recorded state and returns the decision to enforce:
//   - a denial is recorded for the session and its agent process, and its
//     message says the block lasts until the agent restarts;
//   - a call of a session or process that was denied earlier is denied, even
//     when the files are clean now (the agent may still run the hook);
//   - otherwise the snapshot is recorded (replaced at a session start) and
//     the scan's own decision stands.
//
// A record that exists but cannot be read counts as a denial: nothing
// proves the session clean. Writes are best effort: the returned decision
// never depends on one succeeding.
func ApplyForeignHookSession(update SessionUpdate) GuardDecision {
	decision := update.Decision
	home := strings.TrimSpace(update.AccountHome)
	key := update.Key
	if home == "" || !filepath.IsAbs(home) || !key.valid() {
		return decision
	}
	now := update.Now
	if now.IsZero() {
		now = time.Now()
	}
	type loaded struct {
		path   string
		record SessionRecord
		exists bool
	}
	load := func(kind, id string) (loaded, error) {
		if id == "" {
			return loaded{}, nil
		}
		path := SessionPath(home, key.Connector, kind, id)
		record, exists, err := readSessionRecord(path)
		return loaded{path: path, record: record, exists: exists}, err
	}
	process, processErr := load(sessionKindProcess, key.Process)
	session, sessionErr := load(sessionKindSession, key.Session)

	var sticky *SessionRecord
	switch {
	case processErr != nil:
		sticky = unverifiableSessionRecord(key, process.path, processErr)
	case sessionErr != nil:
		sticky = unverifiableSessionRecord(key, session.path, sessionErr)
	}
	if sticky == nil && process.exists && process.record.Blocked {
		sticky = &process.record
	}
	if sticky == nil && session.exists && session.record.Blocked {
		// Another agent process starting this session (a restarted agent
		// resuming it) loaded its hooks from the files the scan just
		// checked, so its snapshot replaces the session's. The process
		// that held the old hooks stays blocked through its own record.
		restarted := update.SessionStart && session.record.Process != "" && key.Process != "" &&
			session.record.Process != key.Process
		if restarted {
			session.exists = false
		} else {
			sticky = &session.record
		}
	}

	state := ForeignHookStateHash(decision.Findings)
	stamp := now.UTC().Format(time.RFC3339)
	fresh := func(existing loaded) SessionRecord {
		record := SessionRecord{Version: 1, Connector: key.Connector, Session: key.Session, Process: key.Process, Started: stamp, State: state}
		if existing.exists && existing.record.Started != "" {
			// Keep the snapshot taken when the session started.
			record.Started, record.State = existing.record.Started, existing.record.State
		}
		return record
	}

	if decision.Deny {
		blocked := func(existing loaded) SessionRecord {
			record := fresh(existing)
			record.Blocked, record.BlockedAt = true, stamp
			for _, finding := range decision.Findings {
				if !finding.Allowed {
					record.Scope, record.Path, record.Digest, record.Reason = finding.Scope, finding.Path, finding.Digest, finding.Reason
					break
				}
			}
			if record.Path == "" && record.Reason == "" {
				record.Reason = "cannot verify hook file: " + truncate(strings.TrimSpace(decision.Reason), 200)
			}
			return record
		}
		for _, entry := range []loaded{process, session} {
			switch {
			case entry.path == "":
			case entry.exists && entry.record.Blocked:
				touchSessionRecord(entry.path, now)
			default:
				_ = writeSessionRecord(entry.path, blocked(entry))
			}
		}
		decision.Reason = strings.TrimSpace(decision.Reason) + " " + sessionBlockNote
		return decision
	}

	if sticky != nil {
		// Carry the block to the other key (a new session of a blocked
		// process, or the process of a blocked session), so it holds even
		// when one of them cannot be named on a later call.
		for _, entry := range []loaded{process, session} {
			if entry.path == "" || (entry.exists && entry.record.Blocked) {
				continue
			}
			if entry.exists && entry.record.Process != "" && key.Process != "" && entry.record.Process != key.Process {
				// Another agent process's clean snapshot of this session
				// (a restarted agent resumed it): leave it to that process.
				continue
			}
			carried := *sticky
			carried.Session, carried.Process = key.Session, key.Process
			if entry.exists && entry.record.Started != "" {
				carried.Started, carried.State = entry.record.Started, entry.record.State
			}
			_ = writeSessionRecord(entry.path, carried)
		}
		for _, entry := range []loaded{process, session} {
			if entry.exists && entry.record.Blocked {
				touchSessionRecord(entry.path, now)
			}
		}
		return stickySessionDecision(decision, key.Connector, *sticky)
	}

	if process.path != "" && !process.exists {
		_ = writeSessionRecord(process.path, fresh(process))
	}
	if session.path != "" && (!session.exists || update.SessionStart) {
		record := fresh(loaded{})
		_ = writeSessionRecord(session.path, record)
	}
	if update.SessionStart {
		pruneSessionRecords(filepath.Join(home, ".defenseclaw", sessionDirName), now)
	}
	return decision
}

// sessionBlockNote ends every denial the session state applies to.
const sessionBlockNote = "The agent can keep running a hook it loaded when the session started, even after the file changes, so DefenseClaw blocks tool calls for the rest of this session: after removing the hook, restart the agent."

func unverifiableSessionRecord(key SessionKey, path string, err error) *SessionRecord {
	return &SessionRecord{
		Connector: key.Connector,
		Blocked:   true,
		Path:      path,
		Reason:    "cannot verify hook file: " + err.Error(),
	}
}

// stickySessionDecision denies a call because an earlier call of the same
// session or agent process was denied for a foreign hook.
func stickySessionDecision(decision GuardDecision, connector string, record SessionRecord) GuardDecision {
	var earlier string
	switch {
	case strings.HasPrefix(record.Reason, "cannot verify"):
		what := strings.TrimPrefix(record.Reason, "cannot verify hook file: ")
		if record.Path != "" && !strings.Contains(what, record.Path) {
			what = record.Path + ": " + what
		}
		earlier = "DefenseClaw could not verify this session's hooks (" + what + ")"
	default:
		what := "defined a hook"
		if record.Reason == "plugin" || record.Reason == "plugin directory" {
			what = "added a plugin"
		}
		scope := record.Scope
		if scope == "" {
			scope = "hook"
		}
		earlier = fmt.Sprintf("the %s file %s %s (digest sha256:%s)", scope, record.Path, what, record.Digest)
	}
	decision.Deny = true
	decision.Reason = fmt.Sprintf(
		"enterprise_foreign_hook_blocked: your organization blocks %s hooks it has not approved, because they can change a tool call after DefenseClaw checks it. Earlier in this agent session %s. %s",
		connector, earlier, sessionBlockNote,
	)
	decision.Findings = append([]Finding{{
		Connector: connector,
		Scope:     record.Scope,
		Path:      record.Path,
		Digest:    record.Digest,
		Reason:    "blocked since earlier in this session: " + record.Reason,
	}}, decision.Findings...)
	return decision
}

// readSessionRecord reads one record without following links. A missing
// record does not exist; anything else that cannot be read or decoded is an
// error.
func readSessionRecord(path string) (SessionRecord, bool, error) {
	data, exists, err := readGuardFileLimit(path, sessionRecordLimit)
	if !exists && err == nil {
		return SessionRecord{}, false, nil
	}
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return SessionRecord{}, false, nil
		}
		return SessionRecord{}, true, err
	}
	var record SessionRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return SessionRecord{}, true, fmt.Errorf("%s: %w", path, err)
	}
	// The record is the user's: bound what a denial message repeats.
	return record.bounded(), true, nil
}

// writeSessionRecord replaces one record atomically.
func writeSessionRecord(path string, record SessionRecord) error {
	record.Version = 1
	data, err := json.Marshal(record.bounded())
	if err != nil {
		return err
	}
	return writePrivateUserFile(path, data)
}

// writePrivateUserFile replaces a small file in the user's data directory
// atomically, refusing a directory or file that is a link.
func writePrivateUserFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a directory", dir)
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	return nil
}

func touchSessionRecord(path string, now time.Time) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || now.Sub(info.ModTime()) < sessionTouchAfter {
		return
	}
	_ = os.Chtimes(path, now, now)
}

// pruneSessionRecords removes records untouched for sessionRecordTTL and,
// past sessionDirLimit records, the oldest ones.
func pruneSessionRecords(dir string, now time.Time) {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return
	}
	handle, err := os.Open(dir)
	if err != nil {
		return
	}
	entries, _ := handle.ReadDir(4 * sessionDirLimit)
	_ = handle.Close()
	type aged struct {
		path string
		mod  time.Time
	}
	var kept []aged
	for _, entry := range entries {
		name := entry.Name()
		path := filepath.Join(dir, name)
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if strings.HasPrefix(name, ".") {
			// A temporary file a crashed writer left behind.
			if now.Sub(info.ModTime()) > time.Hour {
				_ = os.Remove(path)
			}
			continue
		}
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		if now.Sub(info.ModTime()) > sessionRecordTTL {
			_ = os.Remove(path)
			continue
		}
		kept = append(kept, aged{path, info.ModTime()})
	}
	if len(kept) <= sessionDirLimit {
		return
	}
	sort.Slice(kept, func(i, j int) bool { return kept[i].mod.Before(kept[j].mod) })
	for _, entry := range kept[:len(kept)-sessionDirLimit] {
		_ = os.Remove(entry.path)
	}
}

func (r SessionRecord) bounded() SessionRecord {
	clip := func(value string) string {
		value = strings.Map(func(c rune) rune {
			if c < 0x20 || c == 0x7f {
				return ' '
			}
			return c
		}, value)
		if len(value) > blockFieldLimit {
			value = value[:blockFieldLimit]
		}
		return value
	}
	r.Connector, r.Session, r.Process = clip(r.Connector), clip(r.Session), clip(r.Process)
	r.Started, r.State, r.BlockedAt = clip(r.Started), clip(r.State), clip(r.BlockedAt)
	r.Scope, r.Path, r.Digest, r.Reason = clip(r.Scope), clip(r.Path), clip(r.Digest), clip(r.Reason)
	return r
}
