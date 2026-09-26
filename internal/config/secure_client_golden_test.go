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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// The Secure Client golden pins the configuration posture of a
// managed_enterprise config with no enterprise block — the shape every
// production Secure Client install ships today (release branch
// release-defenseclaw-enterprise-26.8.4). A standalone profile must not change
// any of it. See testdata/secure_client_golden/README.md.

type secureClientGoldenCase struct {
	Name     string `json:"name"`
	Input    string `json:"input,omitempty"`
	Result   string `json:"result,omitempty"`
	Error    string `json:"error,omitempty"`
	Resolved string `json:"resolved,omitempty"`
}

func secureClientGoldenError(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func secureClientManagedConfig() *Config {
	return &Config{DeploymentMode: string(DeploymentModeManagedEnterprise)}
}

func TestSecureClientGoldenConfigPosture(t *testing.T) {
	testenv.SkipUnlessSecureClientPlatform(t)
	posture := map[string]any{}

	posture["constants"] = map[string]string{
		"deployment_mode_managed_enterprise": managed.DeploymentModeManagedEnterprise,
		"config_path_env":                    managed.ConfigPathEnv,
		"deployment_mode_env":                managed.DeploymentModeEnv,
		"hook_guardian_auth_dir_env":         managed.HookGuardianAuthorizationDirEnv,
		"hook_guardian_auth_file":            managed.HookGuardianAuthorizationFile,
		"windows_service_account_env":        managed.WindowsServiceAccountEnv,
		"unix_service_account_env":           managed.UnixServiceAccountEnv,
		"secure_client_team_id":              SecureClientTeamID,
		"secure_client_signing_id":           SecureClientSigningID,
		"secure_client_bundle_id":            SecureClientBundleID,
		"env_config_skip_trust_env":          envConfigSkipTrustEnv,
		"env_config_endpoint_key":            envConfigEndpointKey,
	}

	modes := []string{"", "managed_enterprise", " Managed_Enterprise ", "unmanaged_byod", "ci_cd", "server", "saas", "sandboxed"}
	isManaged := map[string]bool{}
	ipc := map[string]bool{}
	peerAuth := map[string]string{}
	for _, mode := range modes {
		cfg := &Config{DeploymentMode: mode}
		isManaged[mode] = managed.IsManagedEnterprise(mode)
		ipc[mode] = cfg.ManagedIPCEnabled()
		peerAuth[mode] = cfg.EffectivePeerAuthKind()
	}
	var nilConfig *Config
	ipc["<nil config>"] = nilConfig.ManagedIPCEnabled()
	posture["is_managed_enterprise"] = isManaged
	posture["managed_ipc_enabled"] = ipc
	posture["effective_peer_auth_kind"] = peerAuth
	posture["default_secure_client_policy"] = DefaultSecureClientPolicy()

	aidSink := map[string]bool{}
	for name, cfg := range map[string]*Config{
		"managed_with_endpoint": {
			DeploymentMode: string(DeploymentModeManagedEnterprise),
			CiscoAIDefense: CiscoAIDefenseConfig{Endpoint: "https://us.api.inspect.aidefense.security.cisco.com"},
		},
		"managed_without_endpoint": {DeploymentMode: string(DeploymentModeManagedEnterprise)},
		"managed_blank_endpoint": {
			DeploymentMode: string(DeploymentModeManagedEnterprise),
			CiscoAIDefense: CiscoAIDefenseConfig{Endpoint: "   "},
		},
		"unmanaged_with_endpoint": {
			DeploymentMode: string(DeploymentModeUnmanagedBYOD),
			CiscoAIDefense: CiscoAIDefenseConfig{Endpoint: "https://us.api.inspect.aidefense.security.cisco.com"},
		},
	} {
		aidSink[name] = cfg.HasManagedAIDLogSink()
	}
	aidSink["<nil config>"] = nilConfig.HasManagedAIDLogSink()
	posture["has_managed_aid_log_sink"] = aidSink

	var bindings []secureClientGoldenCase
	for _, tc := range []struct {
		name         string
		apiBind      string
		guardrail    bool
		guardrailHst string
		mode         string
	}{
		{name: "managed_default_bind", mode: "managed_enterprise"},
		{name: "managed_exact_ipv4", apiBind: "127.0.0.1", mode: "managed_enterprise"},
		{name: "managed_localhost", apiBind: "localhost", mode: "managed_enterprise"},
		{name: "managed_ipv6_loopback", apiBind: "::1", mode: "managed_enterprise"},
		{name: "managed_any", apiBind: "0.0.0.0", mode: "managed_enterprise"},
		{name: "managed_guardrail_default_host", guardrail: true, mode: "managed_enterprise"},
		{name: "managed_guardrail_localhost", guardrail: true, guardrailHst: "localhost", mode: "managed_enterprise"},
		{name: "managed_guardrail_ipv6_loopback", guardrail: true, guardrailHst: "[::1]", mode: "managed_enterprise"},
		{name: "managed_guardrail_remote", guardrail: true, guardrailHst: "10.0.0.5", mode: "managed_enterprise"},
		{name: "unmanaged_any", apiBind: "0.0.0.0", mode: "unmanaged_byod"},
	} {
		cfg := &Config{DeploymentMode: tc.mode}
		cfg.Gateway.APIBind = tc.apiBind
		cfg.Guardrail.Enabled = tc.guardrail
		cfg.Guardrail.Host = tc.guardrailHst
		err := validateManagedEnterpriseListenerBindings(cfg)
		bindings = append(bindings, secureClientGoldenCase{
			Name:     tc.name,
			Input:    tc.apiBind + "|" + tc.guardrailHst,
			Error:    secureClientGoldenError(err),
			Resolved: cfg.Gateway.APIBind,
		})
	}
	posture["listener_bindings"] = bindings

	var knobs []secureClientGoldenCase
	for _, tc := range []struct {
		name string
		cfg  *Config
	}{
		{name: "managed_no_allowlists", cfg: secureClientManagedConfig()},
		{name: "managed_team_ids", cfg: &Config{
			DeploymentMode: string(DeploymentModeManagedEnterprise),
			Managed:        ManagedIPCConfig{AllowedTeamIDs: []string{"ABCDE12345"}},
		}},
		{name: "managed_all_allowlists", cfg: &Config{
			DeploymentMode: string(DeploymentModeManagedEnterprise),
			Managed: ManagedIPCConfig{
				AllowedTeamIDs:    []string{"ABCDE12345"},
				AllowedSigningIDs: []string{"com.example.gui"},
				AllowedBundleIDs:  []string{"com.example.gui"},
			},
		}},
		{name: "unmanaged_team_ids", cfg: &Config{
			DeploymentMode: string(DeploymentModeUnmanagedBYOD),
			Managed:        ManagedIPCConfig{AllowedTeamIDs: []string{"ABCDE12345"}},
		}},
	} {
		knobs = append(knobs, secureClientGoldenCase{
			Name:  tc.name,
			Error: secureClientGoldenError(validateManagedEnterpriseWindowsPeerAuthKnobs(tc.cfg)),
		})
	}
	posture["windows_peer_auth_knobs"] = knobs

	envConfigPath, err := ResolveDefaultEnvConfigPath()
	posture["env_config_default_path"] = secureClientGoldenCase{
		Name:   "resolve_default_env_config_path",
		Result: envConfigPath,
		Error:  secureClientGoldenError(err),
	}

	var endpoints []secureClientGoldenCase
	for _, endpoint := range []string{
		"https://us.api.inspect.aidefense.security.cisco.com",
		"https://preview.api.inspect.aidefense.aiteam.cisco.com",
		"https://127.0.0.1:8443",
		"https://localhost",
		"https://[::1]:9443",
		"http://us.api.inspect.aidefense.security.cisco.com",
		"https://evil.example.com",
		"https://us.api.inspect.aidefense.security.cisco.com.evil.example",
		"https://user:pass@us.api.inspect.aidefense.security.cisco.com",
		"https://us.api.inspect.aidefense.security.cisco.com/api",
		"https://us.api.inspect.aidefense.security.cisco.com?x=1",
		"https://us.api.inspect.aidefense.security.cisco.com#frag",
		"https://",
	} {
		endpoints = append(endpoints, secureClientGoldenCase{
			Name:  "validate_ai_defense_endpoint",
			Input: endpoint,
			Error: secureClientGoldenError(validateAIDefenseEndpoint(endpoint)),
		})
	}
	posture["env_config_endpoint_validation"] = endpoints

	var runtimeMigration []secureClientGoldenCase
	for _, mode := range []string{"managed_enterprise", "unmanaged_byod", ""} {
		for _, requested := range []bool{true, false} {
			runtimeMigration = append(runtimeMigration, secureClientGoldenCase{
				Name:   "guardrail_runtime_migration_allowed",
				Input:  mode + "|" + map[bool]string{true: "requested", false: "not_requested"}[requested],
				Result: map[bool]string{true: "allowed", false: "denied"}[guardrailRuntimeMigrationAllowed(requested, mode)],
			})
		}
	}
	posture["guardrail_runtime_migration"] = runtimeMigration

	testenv.CompareSecureClientGoldenJSONForPlatform(t, "go/config_posture.json", posture)
}

// TestSecureClientGoldenDeploymentModePin pins the loader contract that an
// SCM/launchd environment pin wins over the config file and that a
// contradicting file is refused. The inspection loader is used so the pin
// can be exercised without a root- or Administrators-owned config path.
func TestSecureClientGoldenDeploymentModePin(t *testing.T) {
	testenv.SkipUnlessSecureClientPlatform(t)
	var results []secureClientGoldenCase
	for _, tc := range []struct {
		name string
		pin  string
		yaml string
	}{
		{name: "pin_fills_absent_mode", pin: "managed_enterprise", yaml: "config_version: 8\nobservability: {}\n"},
		{name: "pin_matches_file", pin: "managed_enterprise", yaml: "config_version: 8\ndeployment_mode: managed_enterprise\nobservability: {}\n"},
		{name: "pin_conflicts_with_file", pin: "managed_enterprise", yaml: "config_version: 8\ndeployment_mode: unmanaged_byod\nobservability: {}\n"},
		{name: "invalid_pin", pin: "enterprise", yaml: "config_version: 8\nobservability: {}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(managed.DeploymentModeEnv, tc.pin)
			dir := t.TempDir()
			cfg, err := LoadRuntimeV8InspectionCandidateFromBytes(dir+"/config.yaml", []byte(tc.yaml))
			result := secureClientGoldenCase{Name: tc.name, Input: tc.pin, Error: secureClientGoldenError(err)}
			if cfg != nil {
				result.Resolved = cfg.DeploymentMode
				result.Result = map[bool]string{true: "ipc_enabled", false: "ipc_disabled"}[cfg.ManagedIPCEnabled()]
			}
			results = append(results, result)
		})
	}
	testenv.CompareSecureClientGoldenJSONForPlatform(t, "go/config_mode_pin.json", results)
}
