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

func TestClaudeVersionFloorDefaultsToEnforce(t *testing.T) {
	if got := (EnterpriseMachinePolicyConfig{}).ClaudeVersionFloor(); got != ClaudeVersionFloorEnforce {
		t.Fatalf("default version_floor = %q, want enforce", got)
	}
	m := EnterpriseMachinePolicyConfig{ClaudeCode: EnterpriseClaudeCodePolicyConfig{VersionFloor: " Report "}}
	if got := m.ClaudeVersionFloor(); got != ClaudeVersionFloorReport {
		t.Fatalf("version_floor = %q, want report", got)
	}
}

func TestClaudeVersionFloorValidation(t *testing.T) {
	for _, mode := range []string{"enforce", "report", "off", "OFF"} {
		cfg := Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{MachinePolicy: EnterpriseMachinePolicyConfig{ClaudeCode: EnterpriseClaudeCodePolicyConfig{VersionFloor: mode}}}}
		if err := resolveEnterpriseConfig(&cfg, "linux", ""); err != nil {
			t.Fatalf("version_floor %q rejected: %v", mode, err)
		}
	}
	bad := Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{MachinePolicy: EnterpriseMachinePolicyConfig{ClaudeCode: EnterpriseClaudeCodePolicyConfig{VersionFloor: "strict"}}}}
	if err := resolveEnterpriseConfig(&bad, "linux", ""); err == nil || !strings.Contains(err.Error(), "enterprise.machine_policy.claudecode.version_floor") {
		t.Fatalf("an unknown version_floor must be rejected, got %v", err)
	}
	// The floor is a standalone knob: Secure Client configs keep their exact
	// behavior and refuse it.
	secureClient := Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "secure_client", MachinePolicy: EnterpriseMachinePolicyConfig{ClaudeCode: EnterpriseClaudeCodePolicyConfig{VersionFloor: "off"}}}}
	if err := resolveEnterpriseConfig(&secureClient, "windows", ""); err == nil || !strings.Contains(err.Error(), "apply only to the standalone profile") {
		t.Fatalf("secure_client accepted version_floor: %v", err)
	}
	unmanaged := Config{Enterprise: EnterpriseConfig{MachinePolicy: EnterpriseMachinePolicyConfig{ClaudeCode: EnterpriseClaudeCodePolicyConfig{VersionFloor: "off"}}}}
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
	if err := validate("floor.yaml", "config_version: 8\nenterprise:\n  machine_policy:\n    claudecode:\n      version_floor: report\n"); err != nil {
		t.Fatalf("v8 schema rejected version_floor: %v", err)
	}
	for name, doc := range map[string]string{
		"bad mode":    "config_version: 8\nenterprise:\n  machine_policy:\n    claudecode:\n      version_floor: strict\n",
		"unknown key": "config_version: 8\nenterprise:\n  machine_policy:\n    claudecode:\n      version_ceiling: enforce\n",
	} {
		if err := validate(name+".yaml", doc); err == nil {
			t.Errorf("v8 schema accepted %s", name)
		}
	}
}
