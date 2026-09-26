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

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestResolveEnterpriseConfigProfiles(t *testing.T) {
	cases := []struct {
		name    string
		goos    string
		cfg     Config
		pinned  string
		want    string
		wantErr string
	}{
		{name: "secure client default keeps today's posture", goos: "windows", cfg: Config{DeploymentMode: "managed_enterprise"}, want: managed.ProfileSecureClient},
		{name: "darwin default", goos: "darwin", cfg: Config{DeploymentMode: "managed_enterprise"}, want: managed.ProfileSecureClient},
		{name: "linux default", goos: "linux", cfg: Config{DeploymentMode: "managed_enterprise"}, want: managed.ProfileStandalone},
		{name: "pinned standalone", goos: "windows", cfg: Config{DeploymentMode: "managed_enterprise"}, pinned: "standalone", want: managed.ProfileStandalone},
		{name: "unmanaged ignores empty block", goos: "linux", cfg: Config{}, want: ""},
		{name: "unmanaged rejects block", goos: "linux", cfg: Config{Enterprise: EnterpriseConfig{Enrollment: EnterpriseEnrollmentConfig{Mode: "auto"}}}, wantErr: "requires deployment_mode"},
		{name: "secure client rejects standalone knobs", goos: "windows", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "secure_client", Coexistence: EnterpriseCoexistenceConfig{PerUserInstall: "block"}}}, wantErr: "apply only to the standalone profile"},
		{name: "standalone rejects inline key", goos: "linux", cfg: Config{DeploymentMode: "managed_enterprise", CiscoAIDefense: CiscoAIDefenseConfig{APIKey: "k"}}, wantErr: "protected credential"},
		{name: "standalone requires credential name", goos: "linux", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Inspection: EnterpriseInspectionConfig{AIDefense: EnterpriseAIDefenseConfig{Enabled: true, Credential: "../key"}}}}, wantErr: "protected credential name"},
		{name: "bad enum", goos: "linux", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{MachinePolicy: EnterpriseMachinePolicyConfig{Default: EnterpriseConnectorPolicy{ForeignHooks: "delete"}}}}, wantErr: "foreign_hooks"},
		{name: "bad home root", goos: "linux", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Enrollment: EnterpriseEnrollmentConfig{HomeRoots: []string{"/tmp"}}}}, wantErr: "home parent"},
		{name: "bad signer", goos: "windows", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "standalone", Trust: EnterpriseTrustConfig{AllowedSigners: []string{"abc"}}}}, wantErr: "thumbprint"},
		{name: "bad connector key", goos: "linux", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{MachinePolicy: EnterpriseMachinePolicyConfig{Connectors: map[string]EnterpriseConnectorPolicy{"Bad Name": {}}}}}, wantErr: "connector name"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.cfg
			err := resolveEnterpriseConfig(&cfg, tc.goos, tc.pinned)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("resolveEnterpriseConfig() error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveEnterpriseConfig() unexpected error: %v", err)
			}
			if got := cfg.EnterpriseProfile(); got != tc.want {
				t.Fatalf("EnterpriseProfile() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEnterprisePredicates(t *testing.T) {
	secureClient := &Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "secure_client"}}
	standalone := &Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "standalone"}}
	unmanaged := &Config{Enterprise: EnterpriseConfig{Profile: "standalone"}}
	if !secureClient.ManagedAIDOnly() || !secureClient.SecureClientIntegration() || secureClient.StandaloneEnterprise() {
		t.Fatal("secure client predicates wrong")
	}
	if standalone.ManagedAIDOnly() || standalone.SecureClientIntegration() || !standalone.StandaloneEnterprise() {
		t.Fatal("standalone predicates wrong")
	}
	if unmanaged.ManagedAIDOnly() || unmanaged.StandaloneEnterprise() || unmanaged.EnterpriseProfile() != "" {
		t.Fatal("unmanaged config must not report a profile")
	}
	var nilCfg *Config
	if nilCfg.ManagedAIDOnly() || nilCfg.StandaloneEnterprise() {
		t.Fatal("nil config predicates must be false")
	}
}

func TestMachinePolicyForDefaultsAreSecure(t *testing.T) {
	m := EnterpriseMachinePolicyConfig{
		Default: EnterpriseConnectorPolicy{AllowedHooks: []string{"sha256:" + strings.Repeat("A", 64)}},
		Connectors: map[string]EnterpriseConnectorPolicy{
			"cursor": {ForeignHooks: "report", AllowedHooks: []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}},
		},
	}
	codex := m.PolicyFor("Codex")
	if codex.Ownership != MachinePolicyOwnershipMerge || codex.ManagedHooksOnly != ManagedHooksOnlyEnforce ||
		codex.ForeignHooks != ForeignHooksRemove || codex.HigherPrecedenceSources != HigherPrecedenceFail {
		t.Fatalf("built-in defaults must be secure: %+v", codex)
	}
	cursor := m.PolicyFor("cursor")
	if cursor.ForeignHooks != ForeignHooksReport || cursor.ManagedHooksOnly != ManagedHooksOnlyEnforce {
		t.Fatalf("connector override not applied: %+v", cursor)
	}
	if len(cursor.AllowedHooks) != 2 || cursor.AllowedHooks[0] != strings.Repeat("a", 64) {
		t.Fatalf("allowed hooks not normalized and deduplicated: %v", cursor.AllowedHooks)
	}
}

func TestEnterpriseSelfUpdateDefault(t *testing.T) {
	if !(EnterpriseCoexistenceConfig{}).SelfUpdateDisabled() {
		t.Fatal("self update must be disabled by default on managed hosts")
	}
	off := false
	if (EnterpriseCoexistenceConfig{DisableSelfUpdate: &off}).SelfUpdateDisabled() {
		t.Fatal("explicit false must re-enable self update")
	}
}

func TestConfigV8SchemaAcceptsEnterpriseBlock(t *testing.T) {
	raw := []byte(`config_version: 8
deployment_mode: managed_enterprise
enterprise:
  profile: standalone
  inspection:
    ai_defense:
      enabled: true
      credential: ai-defense-api-key
  enrollment:
    mode: auto
    exclude_users: [ubuntu]
    unenrolled_users: inspect
    home_roots: [/srv/home]
  machine_policy:
    default:
      ownership: merge
      managed_hooks_only: enforce
      foreign_hooks: remove
    connectors:
      cursor:
        foreign_hooks: report
  trust:
    mode: hash_pinned
  coexistence:
    per_user_install: migrate
    disable_self_update: true
  network:
    https_proxy: http://proxy.example.test:3128
`)
	validate := func(name string, data []byte) error {
		document, err := ParseV8YAML(name, data)
		if err != nil {
			return err
		}
		return validateV8Schema(name, document)
	}
	if err := validate("enterprise-v8.yaml", raw); err != nil {
		t.Fatalf("v8 schema rejected the enterprise block: %v", err)
	}
	for name, doc := range map[string]string{
		"unknown profile":    "config_version: 8\nenterprise:\n  profile: saas\n",
		"unknown key":        "config_version: 8\nenterprise:\n  api_key: secret\n",
		"bad credential":     "config_version: 8\nenterprise:\n  inspection:\n    ai_defense:\n      credential: ../x\n",
		"bad connector key":  "config_version: 8\nenterprise:\n  machine_policy:\n    connectors:\n      Bad Name: {}\n",
		"bad foreign policy": "config_version: 8\nenterprise:\n  machine_policy:\n    default:\n      foreign_hooks: delete\n",
		"bad signer":         "config_version: 8\nenterprise:\n  trust:\n    allowed_signers: [abc]\n",
	} {
		if err := validate(name+".yaml", []byte(doc)); err == nil {
			t.Errorf("v8 schema accepted %s", name)
		}
	}
}
