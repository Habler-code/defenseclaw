//go:build !windows

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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Disabling a connector or setting ownership: off removes DefenseClaw's
// earlier entries on the next publish instead of leaving them (and the
// managed-hooks-only lock) until uninstall.
func TestPublishRetiresConnectorsNoLongerPublished(t *testing.T) {
	withHigherSources(t)
	opts := testOptions(t)
	codexFile := codexPath(t, opts)
	writeFile(t, codexFile, adminCodexRequirements)
	if _, err := Publish(opts, []string{"codex", "claudecode", "cursor"}); err != nil {
		t.Fatal(err)
	}

	off := withPolicy(opts, "codex", func(p *config.EnterpriseConnectorPolicy) { p.Ownership = "off" })
	result, err := Publish(off, []string{"codex", "claudecode", "cursor"})
	if err != nil {
		t.Fatal(err)
	}
	if got := readFile(t, codexFile); got != adminCodexRequirements {
		t.Fatalf("ownership: off must restore the administrator requirements:\n%s", got)
	}
	if len(result.Retired) != 1 || result.Retired[0].Connector != "codex" || !result.Changed {
		t.Fatalf("retired = %+v", result.Retired)
	}
	if !result.Complete() {
		t.Fatalf("a retired connector must not make the publish incomplete: %+v", result.States)
	}

	result, err = Publish(off, []string{"codex", "cursor"})
	if err != nil {
		t.Fatal(err)
	}
	mustNotExist(t, claudeDropIn(t, opts), "the drop-in of a disabled connector")
	if len(result.Retired) != 1 || result.Retired[0].Connector != "claudecode" {
		t.Fatalf("retired = %+v", result.Retired)
	}

	verify := withPolicy(off, "cursor", func(p *config.EnterpriseConnectorPolicy) { p.Ownership = "verify_only" })
	result, err = Publish(verify, []string{"codex", "cursor"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Retired) != 0 || !strings.Contains(readFile(t, cursorHooksPath(t, opts)), testHookBinary) {
		t.Fatalf("verify_only keeps DefenseClaw's entries (it still verifies them): %+v", result.Retired)
	}
	if again, err := Publish(verify, []string{"codex", "cursor"}); err != nil || len(again.Retired) != 0 || again.Changed {
		t.Fatalf("retirement must be a one-time change: %+v %v", again, err)
	}
}
