// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"strings"
	"testing"
)

// The Codex, Cursor and Copilot runtimes verify against their stored lock
// alone: a standalone verify must fail once the row records another agent
// version, so the guardian's repair re-renders the hooks for it.
func TestWindowsStandaloneVerifyFailsWhenTheEnrolledVersionMoved(t *testing.T) {
	rendered := InstallResult{Connector: "copilot", AgentVersion: "1.0.40"}
	setStandaloneProfileForTest(t, false)
	if err := requireWindowsStandaloneAgentVersionUnchanged(InstallOptions{ConnectorName: "copilot", AgentVersion: "1.0.90"}, rendered); err != nil {
		t.Fatalf("Secure Client verify changed: %v", err)
	}
	setStandaloneProfileForTest(t, true)
	err := requireWindowsStandaloneAgentVersionUnchanged(InstallOptions{ConnectorName: "copilot", AgentVersion: "1.0.90"}, rendered)
	if err == nil || !strings.Contains(err.Error(), `rendered for agent version "1.0.40", and the enrolled version is now "1.0.90"`) {
		t.Fatalf("standalone verify after an upgrade = %v, want a repair", err)
	}
	if err := requireWindowsStandaloneAgentVersionUnchanged(InstallOptions{ConnectorName: "copilot", AgentVersion: "1.0.40"}, rendered); err != nil {
		t.Fatalf("an unchanged version must verify: %v", err)
	}
	amp := InstallResult{Connector: "amp", AgentVersion: "0.0.1785334225 (released 2026-09-01)"}
	if err := requireWindowsStandaloneAgentVersionUnchanged(InstallOptions{ConnectorName: "amp", AgentVersion: "0.0.1785334225"}, amp); err != nil {
		t.Fatalf("Amp's release suffix is not a version change: %v", err)
	}
}
