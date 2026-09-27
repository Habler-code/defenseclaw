// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// TestValidateHookContractFollowsVerifiedVersionChangesOnlyInStandalone
// covers the standalone version re-check: once an enrolled user's agent
// moves to another version, the standalone guardian re-renders the hooks
// when that version has a known, verified hook contract, refuses a version
// without one (reported as hook_contract_unverified), and the Secure Client
// profile keeps refusing every change.
func TestValidateHookContractFollowsVerifiedVersionChangesOnlyInStandalone(t *testing.T) {
	t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "")
	conn := connector.NewClaudeCodeConnector()
	dataDir := t.TempDir()
	installed := connector.SetupOpts{DataDir: dataDir, AgentVersion: "2.1.154"}
	if err := connector.SaveHookContractLockEntry(dataDir, connector.NewHookContractLockEntry(installed, conn, "test-build")); err != nil {
		t.Fatalf("seed contract lock: %v", err)
	}
	withVersion := func(version string) connector.SetupOpts {
		return connector.SetupOpts{DataDir: dataDir, AgentVersion: version, ManagedEnterprise: true}
	}

	setStandaloneProfileForTest(t, false)
	if err := validateHookContract("action", conn, withVersion("2.1.230")); err == nil ||
		!strings.Contains(err.Error(), "hook contract drift detected") {
		t.Fatalf("Secure Client version change = %v, want the drift refusal", err)
	}

	setStandaloneProfileForTest(t, true)
	for _, version := range []string{"2.1.230", "2.1.200"} {
		if err := validateHookContract("action", conn, withVersion(version)); err != nil {
			t.Fatalf("standalone change to verified version %s = %v, want it accepted for re-render", version, err)
		}
	}
	err := validateHookContract("action", conn, withVersion("2.1.100"))
	if err == nil || !strings.Contains(err.Error(), "is not verified against a known hook contract") {
		t.Fatalf("standalone change to unverified version = %v, want the hook_contract_unverified refusal", err)
	}
}
