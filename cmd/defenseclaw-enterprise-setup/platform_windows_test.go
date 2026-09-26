// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestEnterpriseLifecycleArgumentsUsePublicMachineTransaction(t *testing.T) {
	stage := `C:\ProgramData\DefenseClaw-Enterprise-Setup-0123456789abcdef0123456789abcdef`
	opts := enterpriseSetupOptions{
		Action:                        "install",
		Config:                        `C:\staging\config.yaml`,
		Manifest:                      `C:\staging\targets.yaml`,
		AttestAgentApplicationControl: true,
		AttestClaudeEffectivePolicy:   true,
		NoStart:                       true,
		JSON:                          true,
	}
	want := []string{
		"enterprise", "windows", "install",
		"--installer", filepath.Join(stage, "install-enterprise.ps1"),
		"--broker-binary", filepath.Join(stage, "defenseclaw-cmid-broker.exe"),
		"--gateway-binary", filepath.Join(stage, "defenseclaw-gateway.exe"),
		"--acp-binary", filepath.Join(stage, "defenseclaw-acp.exe"),
		"--hook-binary", filepath.Join(stage, "defenseclaw-hook.exe"),
		"--sensor-helper-binary", filepath.Join(stage, "defenseclaw-sensor-helper.exe"),
		"--cli-binary", filepath.Join(stage, "defenseclaw.exe"),
		"--config", opts.Config,
		"--manifest", opts.Manifest,
		"--no-start", "--json",
		"--attest-agent-application-control",
		"--attest-claude-effective-policy",
	}
	if got := enterpriseLifecycleArguments(stage, opts); !reflect.DeepEqual(got, want) {
		t.Fatalf("enterpriseLifecycleArguments() = %#v, want %#v", got, want)
	}
}

func TestEnterpriseLifecycleReadOnlyDoesNotSupplyReplacementArtifacts(t *testing.T) {
	stage := `C:\ProgramData\DefenseClaw-Enterprise-Setup-0123456789abcdef0123456789abcdef`
	got := enterpriseLifecycleArguments(stage, enterpriseSetupOptions{Action: "status", JSON: true})
	want := []string{
		"enterprise", "windows", "status",
		"--installer", filepath.Join(stage, "install-enterprise.ps1"),
		"--json",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("enterpriseLifecycleArguments() = %#v, want %#v", got, want)
	}
}

func TestEnterpriseLifecycleArgumentsForStandalonePayload(t *testing.T) {
	stage := `C:\ProgramData\DefenseClaw-Enterprise-Setup-0123456789abcdef0123456789abcdef`
	signer := "ab" + strings.Repeat("0", 62)
	got := enterpriseLifecycleArguments(stage, enterpriseSetupOptions{
		Action:             "ensure",
		Config:             `C:\staging\config.yaml`,
		JSON:               true,
		Standalone:         true,
		StandaloneUnsigned: true,
		ProductVersion:     "1.4.0",
		AllowedSigners:     strings.ToUpper(signer),
	})
	want := []string{
		"enterprise", "windows", "ensure",
		"--installer", filepath.Join(stage, "install-enterprise.ps1"),
		"--gateway-binary", filepath.Join(stage, "defenseclaw-gateway.exe"),
		"--acp-binary", filepath.Join(stage, "defenseclaw-acp.exe"),
		"--hook-binary", filepath.Join(stage, "defenseclaw-hook.exe"),
		"--sensor-helper-binary", filepath.Join(stage, "defenseclaw-sensor-helper.exe"),
		"--cli-binary", filepath.Join(stage, "defenseclaw.exe"),
		"--config", `C:\staging\config.yaml`,
		"--json",
		"--profile", "standalone",
		"--product-version", "1.4.0",
		"--trust-mode", "hash_pinned",
		"--payload-manifest", filepath.Join(stage, standalonePayloadTrustName),
		"--allowed-signer", signer,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("enterpriseLifecycleArguments() = %#v, want %#v", got, want)
	}
}
