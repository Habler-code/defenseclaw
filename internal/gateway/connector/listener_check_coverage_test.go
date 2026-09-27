// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestEveryGatewaySenderChecksListenerOwner fails when an embedded hook,
// plugin bridge or the generated notify bridge can send the scoped bearer
// without first running the listener-owner check. Every asset that carries a
// bearer must match one of the rules below, so a new sender cannot be added
// without deciding how it checks the listener.
func TestEveryGatewaySenderChecksListenerOwner(t *testing.T) {
	entries, err := hookFS.ReadDir("hooks")
	if err != nil {
		t.Fatal(err)
	}
	curlCommand := regexp.MustCompile(`(^|\$\(|\s)curl\s`)
	checked := 0
	for _, entry := range entries {
		name := entry.Name()
		data, err := hookFS.ReadFile("hooks/" + name)
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		if !strings.Contains(text, "Bearer") {
			continue
		}
		checked++
		switch {
		case strings.HasSuffix(name, ".sh"):
			check, curl := -1, -1
			for i, line := range strings.Split(text, "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "#") {
					continue
				}
				if check < 0 && strings.Contains(trimmed, `defenseclaw_verify_gateway_listener "${API_ADDR}"`) {
					check = i
				}
				if curl < 0 && curlCommand.MatchString(trimmed) {
					curl = i
				}
			}
			if curl < 0 {
				t.Fatalf("hooks/%s carries a bearer but has no curl request this rule understands", name)
			}
			if check < 0 || check > curl {
				t.Fatalf("hooks/%s runs curl (line %d) before the listener check (line %d)", name, curl+1, check+1)
			}
		case strings.HasSuffix(name, ".js") || strings.HasSuffix(name, ".ts"):
			sends := strings.Count(text, "await fetch(")
			checks := strings.Count(text, "await defenseclawListenerRefusal()") + strings.Count(text, "await listenerRefusal()")
			if !strings.Contains(text, `"{{.ListenerCheckJS}}"`) || sends == 0 || checks != sends {
				t.Fatalf("hooks/%s: %d fetch calls, %d listener checks, check embedded %v",
					name, sends, checks, strings.Contains(text, `"{{.ListenerCheckJS}}"`))
			}
		case strings.HasSuffix(name, ".py"):
			sends := strings.Count(text, "_DIRECT_OPENER.open(")
			checks := strings.Count(text, "refusal = _listener_refusal()")
			if !strings.Contains(text, `_decoded("{{LISTENER_CHECK_B64}}")`) || sends == 0 || checks != sends {
				t.Fatalf("hooks/%s: %d requests, %d listener checks", name, sends, checks)
			}
		default:
			t.Fatalf("hooks/%s carries a bearer; add a listener-check rule for it", name)
		}
	}
	if checked < 15 {
		t.Fatalf("only %d bearer-carrying hook assets were checked", checked)
	}

	// The notify bridge is generated in Go rather than embedded.
	dataDir := t.TempDir()
	if err := writeCodexNotifyBridge(SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970"}); err != nil {
		t.Fatal(err)
	}
	bridge, err := os.ReadFile(filepath.Join(dataDir, "notify-bridge.sh"))
	if err != nil {
		t.Fatal(err)
	}
	check := strings.Index(string(bridge), "defenseclaw_verify_gateway_listener '127.0.0.1:18970'")
	curl := strings.Index(string(bridge), "\ncurl ")
	if check < 0 || curl < 0 || check > curl {
		t.Fatalf("notify bridge listener check at %d, curl at %d", check, curl)
	}
}
