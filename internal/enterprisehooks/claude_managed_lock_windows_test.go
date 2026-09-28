// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"encoding/json"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func claudeLockTestSetup() connector.SetupOpts {
	return connector.SetupOpts{
		APIAddr:           "127.0.0.1:18970",
		HookFailMode:      "closed",
		ManagedEnterprise: true,
		HookExecutable:    `C:\Program Files\Cisco\DefenseClaw\bin\defenseclaw-hook.exe`,
	}
}

// WIN-F37: a standalone process renders and verifies the machine-wide Claude
// Code drop-in with allowManagedHooksOnly: true unless the administrator
// chose managed_hooks_only: preserve; a Secure Client process never does.
func TestWindowsStandaloneClaudePolicyCarriesTheManagedHooksOnlyLock(t *testing.T) {
	t.Cleanup(func() { SetWindowsClaudeManagedHooksOnlyPolicy(nil) })
	provider := connector.NewClaudeCodeConnector()

	setStandaloneProfileForTest(t, true)
	SetWindowsClaudeManagedHooksOnlyPolicy(nil)
	locked := withWindowsClaudeManagedHooksOnly(claudeMachinePolicySetup(claudeLockTestSetup(), "", true))
	if !locked.ClaudeAllowManagedHooksOnly {
		t.Fatal("a standalone process with the default policy renders the Claude drop-in without the lock")
	}
	body, err := provider.ManagedHookPolicy(locked)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	if doc["allowManagedHooksOnly"] != true {
		t.Fatalf("standalone drop-in allowManagedHooksOnly = %v, want true:\n%s", doc["allowManagedHooksOnly"], body)
	}

	SetWindowsClaudeManagedHooksOnlyPolicy(func() bool { return false })
	if withWindowsClaudeManagedHooksOnly(claudeLockTestSetup()).ClaudeAllowManagedHooksOnly {
		t.Fatal("managed_hooks_only: preserve still renders the lock")
	}
	SetWindowsClaudeManagedHooksOnlyPolicy(func() bool { return true })

	setStandaloneProfileForTest(t, false)
	if withWindowsClaudeManagedHooksOnly(claudeLockTestSetup()).ClaudeAllowManagedHooksOnly {
		t.Fatal("a Secure Client process renders the lock")
	}
}

// The version-less identity proof still recognizes the drop-in an earlier
// release published without the lock (so an upgrade can repair it), and the
// locked one, but never another deployment's.
func TestWindowsClaudePolicyIdentityAcceptsTheLockedAndThePreLockPolicy(t *testing.T) {
	t.Cleanup(func() { SetWindowsClaudeManagedHooksOnlyPolicy(nil) })
	setStandaloneProfileForTest(t, true)
	provider := connector.NewClaudeCodeConnector()
	setup := withWindowsClaudeManagedHooksOnly(claudeLockTestSetup())
	for _, contract := range connector.KnownHookContracts("claudecode") {
		for _, lock := range []bool{false, true} {
			rendered := claudeLockTestSetup()
			rendered.HookContractID = contract.ContractID
			rendered.ClaudeAllowManagedHooksOnly = lock
			policy, err := provider.ManagedHookPolicy(rendered)
			if err != nil {
				t.Fatalf("render %s lock=%v: %v", contract.ContractID, lock, err)
			}
			if !claudeManagedPolicyMatchesKnownContract(provider, policy, setup) {
				t.Fatalf("policy for %s lock=%v is not recognized as this deployment's", contract.ContractID, lock)
			}
		}
	}
	other := claudeLockTestSetup()
	other.HookExecutable = `C:\Program Files\Other\hook.exe`
	other.ClaudeAllowManagedHooksOnly = true
	foreign, err := provider.ManagedHookPolicy(other)
	if err != nil {
		t.Fatalf("render foreign policy: %v", err)
	}
	if claudeManagedPolicyMatchesKnownContract(provider, foreign, setup) {
		t.Fatal("a locked policy for another hook executable matched this deployment")
	}
}
