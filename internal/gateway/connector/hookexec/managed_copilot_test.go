// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestManagedCopilotHookDeniesWhenDefenseClawCannotDecide(t *testing.T) {
	sp := specs["copilot"]
	for event, field := range map[string]string{"preToolUse": "permissionDecision", "permissionRequest": "behavior"} {
		var stdout, stderr bytes.Buffer
		opts := Options{Connector: "copilot", Event: event, ManagedEnterprise: true, Stdout: &stdout, Stderr: &stderr}
		if code := failUnreachable(opts, sp, "closed", "enterprise_managed_sid_unregistered"); code != 0 {
			t.Fatalf("%s exit = %d", event, code)
		}
		var body map[string]string
		if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &body); err != nil || body[field] != "deny" {
			t.Fatalf("%s body = %q (%v)", event, stdout.String(), err)
		}
		stdout.Reset()
		if code := failResponse(opts, sp, "closed", "invalid JSON response"); code != 0 || !bytes.Contains(stdout.Bytes(), []byte(`"deny"`)) {
			t.Fatalf("%s response failure = %d %q", event, code, stdout.String())
		}
	}
	// Non-blocking events keep the fail-open result.
	var stdout, stderr bytes.Buffer
	opts := Options{Connector: "copilot", Event: "sessionStart", ManagedEnterprise: true, Stdout: &stdout, Stderr: &stderr}
	if code := failUnreachable(opts, sp, "closed", "x"); code != 0 || stdout.Len() != 0 {
		t.Fatalf("sessionStart = %d %q", code, stdout.String())
	}
	// Per-user (unmanaged) Copilot hooks keep the historical fail-open allow.
	stdout.Reset()
	opts = Options{Connector: "copilot", Event: "preToolUse", Stdout: &stdout, Stderr: &stderr}
	if code := failUnreachable(opts, sp, "closed", "x"); code != 0 || bytes.Contains(stdout.Bytes(), []byte("deny")) {
		t.Fatalf("unmanaged preToolUse = %d %q", code, stdout.String())
	}
}
