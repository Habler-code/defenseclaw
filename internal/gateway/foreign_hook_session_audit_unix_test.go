// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/peercred"
)

// TestForeignHookSessionDenialsAreAudited: a tool call the foreign-hook
// guard denies leaves an audit row with the connector, the account and the
// file, like other blocks, when the session exchange records the block and
// on each later call it enforces, instead of only the guardian's periodic
// journal summary.
func TestForeignHookSessionDenialsAreAudited(t *testing.T) {
	useTestPeerResolver(t, &slowPeerResolver{slowUID: -1, started: make(chan struct{}), release: make(chan struct{})})
	restoreCredentials := hookSocketPeerCredentials
	hookSocketPeerCredentials = func(net.Conn) (peercred.Credentials, error) {
		return peercred.Credentials{UID: 7101, GID: 7101, PID: 301}, nil
	}
	t.Cleanup(func() { hookSocketPeerCredentials = restoreCredentials })
	socket, _, store := startTestHookSocketServerWithLedger(t,
		`{"version":1,"ok":true,"protected_targets":[{"user":"user7101","uid":7101,"connector":"claudecode","ok":true}]}`)
	client := hookSocketClient(socket, 10*time.Second)
	post := func(path string, body any) int {
		t.Helper()
		data, _ := json.Marshal(body)
		request, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:18970"+path, strings.NewReader(string(data)))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-DefenseClaw-Client", "foreign-hook-guard/1.0")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		return response.StatusCode
	}
	hasCaller := func(event audit.Event) bool {
		return event.Structured[auditUserIDKey] == "7101" && event.Structured[auditUserNameKey] == "user7101"
	}

	// A foreign-hook guard denial recorded by the session exchange.
	exchange := map[string]any{
		"key":           map[string]any{"connector": "claudecode", "session": "audit-session", "process": "audit-process"},
		"session_start": true,
		"decision": map[string]any{"deny": true, "reason": "enterprise_foreign_hook_blocked: project hook",
			"findings": []map[string]any{{"connector": "claudecode", "scope": "project", "path": "/repo/.claude/settings.json", "digest": "abcd"}}},
	}
	if status := post("/api/v1/foreign-hook-session/claudecode", exchange); status != http.StatusOK {
		t.Fatalf("session exchange = %d", status)
	}
	denial := waitForAuditRow(t, store, "foreign-hook denial", func(event audit.Event) bool {
		return event.Action == string(audit.ActionConnectorHook) && event.Structured["event"] == "foreign_hook_session" && hasCaller(event)
	})
	extra, _ := denial.Structured["extra"].(map[string]any)
	if denial.Connector != "claudecode" || denial.Structured["action"] != "block" ||
		extra["file"] != "/repo/.claude/settings.json" || extra["session_block"] != "session_recorded" ||
		!strings.Contains(auditStringValue(denial.Structured["reason"]), "enterprise_foreign_hook_blocked") {
		t.Fatalf("denial row connector=%q structured=%v", denial.Connector, denial.Structured)
	}
	// A later call of the blocked session is recorded as an enforced block.
	exchange["session_start"] = false
	exchange["decision"] = map[string]any{"deny": false}
	post("/api/v1/foreign-hook-session/claudecode", exchange)
	waitForAuditRow(t, store, "enforced foreign-hook denial", func(event audit.Event) bool {
		extra, _ := event.Structured["extra"].(map[string]any)
		return event.Structured["event"] == "foreign_hook_session" && extra["session_block"] == "session_enforced" && hasCaller(event)
	})

	// A clean call of a clean session writes no denial row.
	clean := map[string]any{
		"key":           map[string]any{"connector": "claudecode", "session": "clean-session", "process": "clean-process"},
		"session_start": true,
		"decision":      map[string]any{"deny": false},
	}
	post("/api/v1/foreign-hook-session/claudecode", clean)
	events, err := store.ListEvents(500)
	if err != nil {
		t.Fatal(err)
	}
	denials := 0
	for _, event := range events {
		if event.Structured["event"] == "foreign_hook_session" {
			denials++
		}
	}
	if denials != 2 {
		t.Fatalf("foreign-hook denial rows = %d, want 2 (one per denied call)", denials)
	}

	// The caller sends the finding fields: an oversized request still
	// writes a bounded row.
	huge := strings.Repeat("x", 40<<10)
	flood := map[string]any{
		"key":           map[string]any{"connector": "claudecode", "session": "flood-session", "process": "flood-process"},
		"session_start": true,
		"decision": map[string]any{"deny": true, "reason": "enterprise_foreign_hook_blocked: " + huge,
			"findings": []map[string]any{{"connector": "claudecode", "scope": huge, "path": "/repo/" + huge, "digest": huge, "reason": huge}}},
	}
	if status := post("/api/v1/foreign-hook-session/claudecode", flood); status != http.StatusOK {
		t.Fatalf("oversized session exchange = %d", status)
	}
	row := waitForAuditRow(t, store, "oversized foreign-hook denial", func(event audit.Event) bool {
		extra, _ := event.Structured["extra"].(map[string]any)
		file, _ := extra["file"].(string)
		return event.Structured["event"] == "foreign_hook_session" && strings.HasPrefix(file, "/repo/x")
	})
	rowExtra, _ := row.Structured["extra"].(map[string]any)
	for _, key := range []string{"file", "scope", "digest", "finding_reason"} {
		value, _ := rowExtra[key].(string)
		if value == "" || len(value) > foreignHookAuditFieldLimit {
			t.Fatalf("audit field %s has %d bytes, want 1..%d", key, len(value), foreignHookAuditFieldLimit)
		}
	}
	if reason := auditStringValue(row.Structured["reason"]); len(reason) > foreignHookAuditReasonLimit {
		t.Fatalf("audit reason has %d bytes, want at most %d", len(reason), foreignHookAuditReasonLimit)
	}
	if data, _ := json.Marshal(row.Structured); len(data) > 8<<10 {
		t.Fatalf("oversized request wrote a %d-byte audit row", len(data))
	}
}
