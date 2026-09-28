// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/legacyconnector"
)

// The v8 observability compiler reads the file itself: a route selector or
// connector block written for the retired ID keeps applying to its
// replacement, the way the config loader renames the other settings.
func TestParseCompileObservabilityV8RenamesTheRetiredConnector(t *testing.T) {
	retired, replacement := legacyconnector.RetiredDesktopID, legacyconnector.Replacement
	source := "config_version: 8\nobservability:\n" +
		"  connectors:\n    " + retired + ":\n      webhooks: []\n" +
		"  destinations:\n    - name: console\n      kind: console\n      routes:\n" +
		"        - name: desktop\n          signals: [logs]\n          selector:\n" +
		"            buckets: [security.finding]\n            connectors: [codex, " + retired + ", " + replacement + "]\n" +
		"          action: send\n          redaction_profile: none\n"
	compiled, err := ParseCompileObservabilityV8("<test>", []byte(source), ObservabilityV8CompileOptions{DefaultDataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	selector := compiled.Observability.Destinations[0].Routes[0].Selector
	if got := strings.Join(selector.Connectors, ","); got != "codex,"+replacement {
		t.Fatalf("route selector connectors = %q, want codex and %s once", got, replacement)
	}
	if _, ok := compiled.Observability.Connectors[retired]; ok {
		t.Fatalf("retired observability.connectors key survived: %v", compiled.Observability.Connectors)
	}
	if _, ok := compiled.Observability.Connectors[replacement]; !ok {
		t.Fatalf("observability.connectors lacks %s: %v", replacement, compiled.Observability.Connectors)
	}
}
