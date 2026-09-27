// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func claudeFloorPolicy(mode string) EnterpriseMachinePolicyConfig {
	return EnterpriseMachinePolicyConfig{Connectors: map[string]EnterpriseConnectorPolicy{"claudecode": {VersionFloor: mode}}}
}

func TestClaudeVersionFloorDefaultsToEnforce(t *testing.T) {
	if got := (EnterpriseMachinePolicyConfig{}).ClaudeVersionFloor(); got != ClaudeVersionFloorEnforce {
		t.Fatalf("default version_floor = %q, want enforce", got)
	}
	if got := claudeFloorPolicy(" Report ").ClaudeVersionFloor(); got != ClaudeVersionFloorReport {
		t.Fatalf("version_floor = %q, want report", got)
	}
	// Other claudecode keys leave the floor at its default, and the floor
	// leaves them at theirs.
	m := EnterpriseMachinePolicyConfig{Connectors: map[string]EnterpriseConnectorPolicy{"claudecode": {Ownership: "verify_only"}}}
	if got := m.ClaudeVersionFloor(); got != ClaudeVersionFloorEnforce {
		t.Fatalf("version_floor = %q, want enforce", got)
	}
	if got := claudeFloorPolicy("off").PolicyFor("claudecode"); got.Ownership != MachinePolicyOwnershipMerge || got.ManagedHooksOnly != ManagedHooksOnlyEnforce {
		t.Fatalf("version_floor changed the other claudecode keys: %+v", got)
	}
}

func TestClaudeVersionFloorValidation(t *testing.T) {
	managedConfig := func(m EnterpriseMachinePolicyConfig) Config {
		return Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{MachinePolicy: m}}
	}
	for _, mode := range []string{"enforce", "report", "off", "OFF"} {
		cfg := managedConfig(claudeFloorPolicy(mode))
		if err := resolveEnterpriseConfig(&cfg, "linux", ""); err != nil {
			t.Fatalf("version_floor %q rejected: %v", mode, err)
		}
	}
	bad := managedConfig(claudeFloorPolicy("strict"))
	if err := resolveEnterpriseConfig(&bad, "linux", ""); err == nil || !strings.Contains(err.Error(), "enterprise.machine_policy.connectors.claudecode.version_floor") {
		t.Fatalf("an unknown version_floor must be rejected, got %v", err)
	}
	// The key belongs to connectors.claudecode only: default does not carry
	// it, and no other connector has a version floor.
	for name, m := range map[string]EnterpriseMachinePolicyConfig{
		"enterprise.machine_policy.default.version_floor":          {Default: EnterpriseConnectorPolicy{VersionFloor: "off"}},
		"enterprise.machine_policy.connectors.codex.version_floor": {Connectors: map[string]EnterpriseConnectorPolicy{"codex": {VersionFloor: "off"}}},
	} {
		cfg := managedConfig(m)
		if err := resolveEnterpriseConfig(&cfg, "linux", ""); err == nil || !strings.Contains(err.Error(), name+" is not a setting") || !strings.Contains(err.Error(), "connectors.claudecode.version_floor") {
			t.Fatalf("%s must be rejected and name the right key, got %v", name, err)
		}
	}
	// The floor is a standalone knob: Secure Client configs keep their exact
	// behavior and refuse it.
	secureClient := managedConfig(claudeFloorPolicy("off"))
	secureClient.Enterprise.Profile = "secure_client"
	if err := resolveEnterpriseConfig(&secureClient, "windows", ""); err == nil || !strings.Contains(err.Error(), "apply only to the standalone profile") {
		t.Fatalf("secure_client accepted version_floor: %v", err)
	}
	unmanaged := Config{Enterprise: EnterpriseConfig{MachinePolicy: claudeFloorPolicy("off")}}
	if err := resolveEnterpriseConfig(&unmanaged, "linux", ""); err == nil || !strings.Contains(err.Error(), "requires deployment_mode") {
		t.Fatalf("an unmanaged config accepted version_floor: %v", err)
	}
}

func TestConfigV8SchemaAcceptsClaudeVersionFloor(t *testing.T) {
	validate := func(name, doc string) error {
		document, err := ParseV8YAML(name, []byte(doc))
		if err != nil {
			return err
		}
		return validateV8Schema(name, document)
	}
	const head = "config_version: 8\nenterprise:\n  machine_policy:\n"
	for name, doc := range map[string]string{
		"version_floor":         head + "    connectors:\n      claudecode:\n        version_floor: report\n",
		"with the other keys":   head + "    connectors:\n      claudecode:\n        ownership: merge\n        managed_hooks_only: preserve\n        allowed_hooks: [\"sha256:" + strings.Repeat("a", 64) + "\"]\n        version_floor: \"off\"\n",
		"other connectors keep": head + "    connectors:\n      codex:\n        ownership: verify_only\n",
	} {
		if err := validate(name+".yaml", doc); err != nil {
			t.Fatalf("v8 schema rejected %s: %v", name, err)
		}
	}
	for name, doc := range map[string]string{
		"bad mode":               head + "    connectors:\n      claudecode:\n        version_floor: strict\n",
		"unknown key":            head + "    connectors:\n      claudecode:\n        version_ceiling: enforce\n",
		"another connector":      head + "    connectors:\n      codex:\n        version_floor: enforce\n",
		"the default block":      head + "    default:\n      version_floor: enforce\n",
		"a top-level claudecode": head + "    claudecode:\n      version_floor: enforce\n",
	} {
		if err := validate(name+".yaml", doc); err == nil {
			t.Errorf("v8 schema accepted %s", name)
		}
	}
}
