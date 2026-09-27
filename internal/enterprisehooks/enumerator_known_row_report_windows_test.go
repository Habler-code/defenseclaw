// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import "testing"

// A known row dropped because the user removed the agent is no gap and is
// not reported; one dropped while the agent is still installed is.
func TestStandaloneDroppedKnownRowIsReportedOnlyWhileInstalled(t *testing.T) {
	stubMachineWinGet(t, nil)
	enabled := true
	prior := ManifestTarget{SID: testLocalUserSID, Connector: "codex", AgentVersion: "0.125.0", Enabled: &enabled}
	previous := map[string]ManifestTarget{previousManifestKey(prior.SID, prior.Connector): prior}
	var reported []UnprotectedAgent
	rowContext := windowsStandaloneRowContext{user: "alice", report: func(agent UnprotectedAgent) { reported = append(reported, agent) }}

	removed := ManifestTarget{SID: testLocalUserSID, Connector: "codex", UserHome: t.TempDir()}
	if applyStandaloneRowStateFor(&removed, previous, nil, rowContext) || len(reported) != 0 {
		t.Fatalf("removed agent: emitted=%+v reported=%+v, want dropped and not reported", removed, reported)
	}

	installed := ManifestTarget{SID: testLocalUserSID, Connector: "codex", UserHome: codexProfile(t, "0.125.0")}
	if applyStandaloneRowStateFor(&installed, previous, nil, rowContext) {
		t.Fatalf("a row below the Windows minimum must be dropped: %+v", installed)
	}
	if len(reported) != 1 || reported[0].Version != "0.125.0" || reported[0].Code != UnprotectedCodeAgentUnprotected {
		t.Fatalf("reported = %+v, want the installed agent below the minimum", reported)
	}
}
