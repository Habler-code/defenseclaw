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

// waitForAuditRow polls the audit store until match finds a row.
func waitForAuditRow(t *testing.T, store *audit.Store, what string, match func(audit.Event) bool) audit.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		events, err := store.ListEvents(500)
		if err != nil {
			t.Fatal(err)
		}
		for _, event := range events {
			if match(event) {
				return event
			}
		}
		if time.Now().After(deadline) {
			actions := make([]string, 0, len(events))
			for _, event := range events {
				actions = append(actions, event.Action)
			}
			t.Fatalf("no %s audit row; rows: %v", what, actions)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestHookSocketAuditRowsNameTheVerifiedCaller: the rows an administrator
// reviews for a standalone user's calls (rejected connector hooks, direct
// inspect calls, refused requests and foreign-hook guard denials) name the
// kernel-verified account, the connector and, for refusals, the route and
// reason, instead of leaving them to the gateway journal.
func TestHookSocketAuditRowsNameTheVerifiedCaller(t *testing.T) {
	useTestPeerResolver(t, &slowPeerResolver{slowUID: -1, started: make(chan struct{}), release: make(chan struct{})})
	restoreCredentials := hookSocketPeerCredentials
	hookSocketPeerCredentials = func(net.Conn) (peercred.Credentials, error) {
		return peercred.Credentials{UID: 7101, GID: 7101, PID: 301}, nil
	}
	t.Cleanup(func() { hookSocketPeerCredentials = restoreCredentials })
	socket, _, store := startTestHookSocketServerWithLedger(t,
		`{"version":1,"ok":true,"protected_targets":[{"user":"user7101","uid":7101,"connector":"claudecode","ok":true}]}`)
	client := hookSocketClient(socket, 10*time.Second)
	post := func(path, connectorName string, body any) int {
		t.Helper()
		data, _ := json.Marshal(body)
		request, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:18970"+path, strings.NewReader(string(data)))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-DefenseClaw-Client", "claude-code-hook/1.0")
		if connectorName != "" {
			request.Header.Set("X-DefenseClaw-Connector", connectorName)
		}
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

	// A rejected connector hook (no event name).
	post("/api/v1/claude-code/hook", "", map[string]any{})
	waitForAuditRow(t, store, "rejected connector-hook with the caller", func(event audit.Event) bool {
		return event.Action == string(audit.ActionConnectorHook) && event.Structured["result"] == "rejected" && hasCaller(event)
	})

	// A direct inspect call.
	if status := post("/api/v1/inspect/tool", "claudecode", map[string]any{"tool": "Bash", "args": map[string]any{"command": "echo attribution"}}); status != http.StatusOK {
		t.Fatalf("inspect = %d", status)
	}
	inspect := waitForAuditRow(t, store, "inspect-tool row with the caller", func(event audit.Event) bool {
		return strings.HasPrefix(event.Action, "inspect-tool-") && hasCaller(event)
	})
	if inspect.Connector != "claudecode" || inspect.Structured["route"] != "/api/v1/inspect/tool" {
		t.Fatalf("inspect row connector=%q structured=%v", inspect.Connector, inspect.Structured)
	}

	// A refused request: the caller is not enrolled for cursor.
	if status := post("/api/v1/cursor/hook", "", map[string]any{"hook_event_name": "beforeShellExecution"}); status != http.StatusForbidden {
		t.Fatalf("unenrolled connector = %d", status)
	}
	refusal := waitForAuditRow(t, store, "api-auth-failure with the principal", func(event audit.Event) bool {
		return event.Action == string(audit.ActionAPIAuthFailure) && event.Structured["defenseclaw.admin.principal_ref"] == "uid:7101"
	})
	if refusal.Structured["defenseclaw.admin.reason"] != managedHookReasonUIDUnregistered ||
		!strings.Contains(auditStringValue(refusal.Structured["defenseclaw.admin.target_ref"]), "/api/v1/cursor/hook") ||
		refusal.Connector != "cursor" {
		t.Fatalf("refusal row connector=%q structured=%v", refusal.Connector, refusal.Structured)
	}
}

func auditStringValue(value any) string {
	text, _ := value.(string)
	return text
}
