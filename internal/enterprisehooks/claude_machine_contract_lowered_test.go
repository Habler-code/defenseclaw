// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"strings"
	"testing"
)

// Only a Claude Code change to an older hook contract is refused: it would
// lower the one machine-wide policy every user shares.
func TestClaudeMachineContractLoweredOnlyForAnOlderClaudeContract(t *testing.T) {
	for _, tc := range []struct {
		connector, from, to string
		lowered             bool
	}{
		{"claudecode", "2.1.230", "2.1.160", true},
		{"ClaudeCode", "2.1.230", "2.1.160", true},
		{"claudecode", "2.1.160", "2.1.230", false}, // an upgrade
		{"claudecode", "2.1.230", "2.1.240", false}, // the same contract
		{"claudecode", "", "2.1.160", false},        // nothing verified to keep
		{"claudecode", "2.1.230", "1.0.0", false},   // no contract: admission refuses it
		{"codex", "0.150.0", "0.142.0", false},      // per-user hooks only
	} {
		reason := claudeMachineContractLowered(tc.connector, tc.from, tc.to)
		if (reason != "") != tc.lowered {
			t.Errorf("%s %s -> %s: reason %q, want lowered=%t", tc.connector, tc.from, tc.to, reason, tc.lowered)
		}
		if tc.lowered && !strings.Contains(reason, "machine-wide Claude Code policy every user shares") {
			t.Errorf("reason %q must say the policy is shared", reason)
		}
	}
}
