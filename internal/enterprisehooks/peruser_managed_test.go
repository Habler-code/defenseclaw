// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestWindowsStandalonePerUserBuiltinRejectsImpostors(t *testing.T) {
	// A built-in of a different name must not satisfy the check.
	if isWindowsStandalonePerUserBuiltin("copilot", connector.NewDevinConnector()) {
		t.Fatal("devin implementation accepted as copilot")
	}
	if isWindowsStandalonePerUserBuiltin("amp", connector.NewOpenCodeConnector()) {
		t.Fatal("opencode implementation accepted as amp")
	}
	if isWindowsStandalonePerUserBuiltin("codex", connector.NewCodexConnector()) {
		t.Fatal("codex is not a per-user connector")
	}
	if !isWindowsStandalonePerUserBuiltin("amp", connector.NewAMPConnector()) {
		t.Fatal("built-in amp rejected")
	}
}

func TestWindowsStandalonePerUserConnectorRuntimeKinds(t *testing.T) {
	for name, wantHookBinary := range map[string]bool{
		"copilot": true, "antigravity": true, "devin": true, "hermes": true,
		"opencode": false, "amp": false,
	} {
		hookBinary, ok := windowsStandalonePerUserConnector(name)
		if !ok || hookBinary != wantHookBinary {
			t.Fatalf("%s: hookBinary=%t ok=%t", name, hookBinary, ok)
		}
	}
	for _, name := range []string{"codex", "claudecode", "cursor", "openhands", ""} {
		if _, ok := windowsStandalonePerUserConnector(name); ok {
			t.Fatalf("%q classified as per-user", name)
		}
	}
}

func TestWindowsEnterpriseRefusedConnectorReasons(t *testing.T) {
	for _, name := range []string{"openhands", "omnigent", "geminicli", "windsurf", "kiro"} {
		if reason := WindowsEnterpriseRefusedConnectorReason(name); strings.TrimSpace(reason) == "" {
			t.Fatalf("%s has no refusal reason", name)
		}
	}
	if !strings.Contains(WindowsEnterpriseRefusedConnectorReason("kiro"), "enterprise acp") {
		t.Fatal("kiro refusal does not point at enterprise acp")
	}
	if WindowsEnterpriseRefusedConnectorReason("copilot") != "" {
		t.Fatal("managed connector reported as refused")
	}
}
