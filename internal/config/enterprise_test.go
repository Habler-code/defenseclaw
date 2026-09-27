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
	"os"
	"path/filepath"
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
		{name: "pinned standalone", goos: "windows", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "standalone"}}, pinned: "standalone", want: managed.ProfileStandalone},
		{name: "pinned standalone needs a declared profile on windows", goos: "windows", cfg: Config{DeploymentMode: "managed_enterprise"}, pinned: "standalone", wantErr: "enterprise.profile must be set to standalone"},
		{name: "pinned standalone needs a declared profile on darwin", goos: "darwin", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Inspection: EnterpriseInspectionConfig{AIDefense: EnterpriseAIDefenseConfig{Enabled: true, Credential: "ai-defense-api-key"}}}}, pinned: "standalone", wantErr: "enterprise.profile must be set to standalone"},
		{name: "pinned standalone on linux may leave the profile unset", goos: "linux", cfg: Config{DeploymentMode: "managed_enterprise"}, pinned: "standalone", want: managed.ProfileStandalone},
		{name: "unmanaged ignores empty block", goos: "linux", cfg: Config{}, want: ""},
		{name: "unmanaged rejects block", goos: "linux", cfg: Config{Enterprise: EnterpriseConfig{Enrollment: EnterpriseEnrollmentConfig{Mode: "auto"}}}, wantErr: "requires deployment_mode"},
		{name: "secure client rejects standalone knobs", goos: "windows", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "secure_client", Coexistence: EnterpriseCoexistenceConfig{PerUserInstall: "block"}}}, wantErr: "apply only to the standalone profile"},
		{name: "standalone rejects inline key", goos: "linux", cfg: Config{DeploymentMode: "managed_enterprise", CiscoAIDefense: CiscoAIDefenseConfig{APIKey: "k"}}, wantErr: "protected credential"},
		{name: "standalone requires credential name", goos: "linux", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Inspection: EnterpriseInspectionConfig{AIDefense: EnterpriseAIDefenseConfig{Enabled: true, Credential: "../key"}}}}, wantErr: "protected credential name"},
		{name: "bad enum", goos: "linux", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{MachinePolicy: EnterpriseMachinePolicyConfig{Default: EnterpriseConnectorPolicy{ForeignHooks: "delete"}}}}, wantErr: "foreign_hooks"},
		{name: "bad home root", goos: "linux", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Enrollment: EnterpriseEnrollmentConfig{HomeRoots: []string{"/tmp"}}}}, wantErr: "home parent"},
		{name: "bad signer", goos: "windows", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "standalone", Trust: EnterpriseTrustConfig{AllowedSigners: []string{"abc"}}}}, wantErr: "thumbprint"},
		{name: "bad connector key", goos: "linux", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{MachinePolicy: EnterpriseMachinePolicyConfig{Connectors: map[string]EnterpriseConnectorPolicy{"Bad Name": {}}}}}, wantErr: "connector name"},
		{name: "proxy with credentials", goos: "windows", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "standalone", Network: EnterpriseNetworkConfig{HTTPSProxy: "http://u:p@proxy.corp:3128"}}}, wantErr: "enterprise.network.https_proxy"},
		{name: "proxy without scheme", goos: "linux", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Network: EnterpriseNetworkConfig{HTTPSProxy: "proxy.corp:3128"}}}, wantErr: "enterprise.network.https_proxy"},
		{name: "valid proxy", goos: "linux", cfg: Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Network: EnterpriseNetworkConfig{HTTPSProxy: "http://proxy.corp:3128", NoProxy: "internal.corp"}}}, want: managed.ProfileStandalone},
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
			if got, want := cfg.DeclaredEnterpriseProfile(), managed.NormalizeEnterpriseProfile(tc.cfg.Enterprise.Profile); managed.IsManagedEnterprise(tc.cfg.DeploymentMode) && got != want {
				t.Fatalf("DeclaredEnterpriseProfile() = %q, want %q", got, want)
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
	unresolved := &Config{DeploymentMode: "managed_enterprise"}
	if !unresolved.ManagedAIDOnly() || unresolved.EnterpriseProfile() != managed.ProfileSecureClient {
		t.Fatal("a managed config built without the loader must keep the Secure Client posture")
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

func TestStandaloneDropsSecureClientSurfaces(t *testing.T) {
	standalone := &Config{
		DeploymentMode: "managed_enterprise",
		Enterprise:     EnterpriseConfig{Profile: "standalone"},
		CiscoAIDefense: CiscoAIDefenseConfig{Endpoint: "https://us.api.inspect.aidefense.security.cisco.com"},
	}
	if standalone.HasManagedAIDLogSink() {
		t.Fatal("standalone must not require the CMID-authenticated AI Defense sink")
	}
	if standalone.ManagedIPCEnabled() {
		t.Fatal("standalone has no Secure Client GUI and must not expose IPC")
	}
	secureClient := &Config{
		DeploymentMode: "managed_enterprise",
		CiscoAIDefense: CiscoAIDefenseConfig{Endpoint: "https://us.api.inspect.aidefense.security.cisco.com"},
	}
	if !secureClient.HasManagedAIDLogSink() || !secureClient.ManagedIPCEnabled() {
		t.Fatal("Secure Client surfaces must stay enabled for an unprofiled managed config")
	}
}

func TestManagedAIDDestinationSkippedForStandalone(t *testing.T) {
	plan := &ObservabilityV8Plan{}
	got, err := WithObservabilityV8ManagedAIDDestination(plan, ObservabilityV8ManagedAIDOptions{
		DeploymentMode: "managed_enterprise",
		Profile:        "standalone",
		Endpoint:       "https://us.api.inspect.aidefense.security.cisco.com",
	})
	if err != nil || got != plan {
		t.Fatalf("standalone must leave the observability plan untouched: plan=%p got=%p err=%v", plan, got, err)
	}
}

func TestStandalonePolicyInputsMustBeAdministratorControlled(t *testing.T) {
	cfg := &Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "standalone"}}
	cfg.PolicyDir = filepath.Join(t.TempDir(), "absent")
	if err := validateManagedStandalonePolicyInputs(cfg); err != nil {
		t.Fatalf("absent policy dirs fall back to embedded rule packs: %v", err)
	}
	if os.Geteuid() == 0 {
		t.Skip("a root-owned temp dir is trusted; the negative case needs a non-root owner")
	}
	cfg.PolicyDir = t.TempDir()
	if err := validateManagedStandalonePolicyInputs(cfg); err == nil || !strings.Contains(err.Error(), "not administrator-controlled") {
		t.Fatalf("user-owned policy dir must be rejected, got %v", err)
	}
	secureClient := &Config{DeploymentMode: "managed_enterprise", PolicyDir: t.TempDir()}
	if err := validateManagedStandalonePolicyInputs(secureClient); err != nil {
		t.Fatalf("Secure Client never consults local policy inputs: %v", err)
	}
}

// The loader's implicit rule pack lives under data_dir, which the
// standalone gateway can write; standalone keeps it inside policy_dir.
func TestStandaloneImplicitRulePackFollowsPolicyDir(t *testing.T) {
	implicit := filepath.Join("/var/lib/defenseclaw", "policies", "guardrail", "default")
	cases := []struct {
		name    string
		goos    string
		policy  string
		pack    string
		profile string
		want    string
	}{
		{name: "standalone implicit follows policy_dir", goos: "linux", policy: "/opt/defenseclaw/share/policies", pack: implicit, want: "/opt/defenseclaw/share/policies/guardrail/default"},
		{name: "standalone explicit pack is kept", goos: "linux", policy: "/opt/defenseclaw/share/policies", pack: "/etc/defenseclaw/policies/guardrail/custom", want: "/etc/defenseclaw/policies/guardrail/custom"},
		{name: "standalone with data_dir policies is unchanged", goos: "linux", policy: "/var/lib/defenseclaw/policies", pack: implicit, want: implicit},
		{name: "secure client is unchanged", goos: "windows", policy: "/opt/defenseclaw/share/policies", pack: implicit, profile: managed.ProfileSecureClient, want: implicit},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := Config{DeploymentMode: "managed_enterprise", DataDir: "/var/lib/defenseclaw", PolicyDir: tc.policy}
			cfg.Guardrail.RulePackDir = tc.pack
			cfg.Enterprise.Profile = tc.profile
			if err := resolveEnterpriseConfig(&cfg, tc.goos, ""); err != nil {
				t.Fatal(err)
			}
			if cfg.Guardrail.RulePackDir != tc.want {
				t.Fatalf("rule_pack_dir = %q, want %q", cfg.Guardrail.RulePackDir, tc.want)
			}
		})
	}
}

func TestEnterpriseAgentPrefixes(t *testing.T) {
	for prefix, wantErr := range map[string]string{
		"/opt/tools":         "",
		"/usr/local/company": "",
		"relative/path":      "clean absolute path",
		"/opt/a:/opt/b":      "clean absolute path",
		"/opt/../home/x":     "clean absolute path",
		"/":                  "not an install prefix",
		"/home/alice/.npm":   "users can write",
		"/tmp/agents":        "users can write",
		"/Users/bob/tools":   "users can write",
	} {
		cfg := Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Enrollment: EnterpriseEnrollmentConfig{AgentPrefixes: []string{prefix}}}}
		err := resolveEnterpriseConfig(&cfg, "linux", "")
		if wantErr == "" {
			if err != nil {
				t.Fatalf("agent prefix %q rejected: %v", prefix, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), wantErr) {
			t.Fatalf("agent prefix %q error = %v, want %q", prefix, err, wantErr)
		}
	}
	// Secure Client keeps rejecting standalone-only enrollment knobs.
	cfg := Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "secure_client", Enrollment: EnterpriseEnrollmentConfig{AgentPrefixes: []string{"/opt/tools"}}}}
	if err := resolveEnterpriseConfig(&cfg, "windows", ""); err == nil {
		t.Fatal("secure_client accepted enrollment.agent_prefixes")
	}
}

func TestEnterpriseEnrollmentUIDMax(t *testing.T) {
	for _, tc := range []struct {
		min, max int
		wantErr  string
	}{
		{0, 0, ""}, {1000, 2000000000, ""}, {0, 70000, ""},
		{0, -1, "uid_max must not be negative"},
		{5000, 4000, "must not be below uid_min"},
	} {
		cfg := Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Enrollment: EnterpriseEnrollmentConfig{UIDMin: tc.min, UIDMax: tc.max}}}
		err := resolveEnterpriseConfig(&cfg, "linux", "")
		if tc.wantErr == "" && err != nil {
			t.Fatalf("uid range %d-%d rejected: %v", tc.min, tc.max, err)
		}
		if tc.wantErr != "" && (err == nil || !strings.Contains(err.Error(), tc.wantErr)) {
			t.Fatalf("uid range %d-%d error = %v, want %q", tc.min, tc.max, err, tc.wantErr)
		}
	}
	document, err := ParseV8YAML("uid-max.yaml", []byte("config_version: 8\nenterprise:\n  enrollment:\n    uid_max: 2000000000\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateV8Schema("uid-max.yaml", document); err != nil {
		t.Fatalf("v8 schema rejected enrollment.uid_max: %v", err)
	}
	cfg := Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "secure_client", Enrollment: EnterpriseEnrollmentConfig{UIDMax: 70000}}}
	if err := resolveEnterpriseConfig(&cfg, "windows", ""); err == nil {
		t.Fatal("secure_client accepted enrollment.uid_max")
	}
}
