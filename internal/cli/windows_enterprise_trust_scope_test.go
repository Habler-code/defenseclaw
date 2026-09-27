// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// stubWindowsEnterpriseRecordedTrust makes the production standalone record
// report trust (after stubWindowsEnterpriseDeployments, whose cleanup
// restores the real inspector).
func stubWindowsEnterpriseRecordedTrust(t *testing.T, trust *string) {
	t.Helper()
	inner := windowsEnterpriseDeploymentInspector
	windowsEnterpriseDeploymentInspector = func(profile string) (winpath.EnterpriseDeployment, error) {
		deployment, err := inner(profile)
		if profile == "standalone" {
			deployment.TrustMode = *trust
			deployment.MetadataPath = `C:\ProgramData\Cisco\DefenseClaw\install\deployment.json`
		}
		return deployment, err
	}
}

// Without a payload manifest the installer re-admits a hash-pinned
// deployment's payload by its recorded pins and keeps it hash-pinned, even
// when --trust-mode is omitted or authenticode. mode authenticode therefore
// refuses a mutation over such a deployment before any change, as it refuses
// --trust-mode hash_pinned, whether the config is supplied or installed.
func TestWindowsEnterpriseAuthenticodeConfigRefusesARecordedHashPinnedDeployment(t *testing.T) {
	stubWindowsEnterpriseDeployments(t, map[string]winpath.EnterpriseDeploymentState{"standalone": winpath.EnterpriseDeploymentInstalled})
	recorded := "hash_pinned"
	stubWindowsEnterpriseRecordedTrust(t, &recorded)
	dir := t.TempDir()
	authenticode := writeWindowsEnterpriseTrustConfig(t, dir, "authenticode.yaml", "  trust:\n    mode: authenticode\n")
	hashPinned := writeWindowsEnterpriseTrustConfig(t, dir, "hash.yaml", "  trust:\n    mode: hash_pinned\n")
	unset := writeWindowsEnterpriseTrustConfig(t, dir, "unset.yaml", "")
	refused := func(t *testing.T, action string, opts *windowsEnterpriseLifecycleOptions) {
		t.Helper()
		err := resolveWindowsEnterpriseLifecycleProfile(action, opts)
		if err == nil || !errors.Is(err, errWindowsEnterpriseInvalidArguments) ||
			!strings.Contains(err.Error(), "is hash_pinned") ||
			!strings.Contains(err.Error(), `install\deployment.json`) {
			t.Fatalf("%s: err = %v, want the recorded hash_pinned trust refused as invalid arguments", action, err)
		}
	}
	accepted := func(t *testing.T, action string, opts *windowsEnterpriseLifecycleOptions) {
		t.Helper()
		if err := resolveWindowsEnterpriseLifecycleProfile(action, opts); err != nil {
			t.Fatalf("%s: %v", action, err)
		}
	}

	for _, action := range []string{"install", "upgrade", "repair", "ensure"} {
		refused(t, action, &windowsEnterpriseLifecycleOptions{configPath: authenticode})
		refused(t, action, &windowsEnterpriseLifecycleOptions{configPath: authenticode, trustMode: "authenticode"})
	}
	// Read-only actions and uninstall bring no payload.
	for _, action := range []string{"status", "verify", "uninstall"} {
		accepted(t, action, &windowsEnterpriseLifecycleOptions{configPath: authenticode})
	}
	// A config that admits the hash-pinned deployment keeps working.
	accepted(t, "ensure", &windowsEnterpriseLifecycleOptions{configPath: hashPinned})
	accepted(t, "ensure", &windowsEnterpriseLifecycleOptions{configPath: unset})

	// The installed config applies to a remediation run without --config.
	windowsEnterpriseInstalledConfigPath = func() (string, error) { return authenticode, nil }
	refused(t, "ensure", &windowsEnterpriseLifecycleOptions{profile: "standalone"})
	refused(t, "repair", &windowsEnterpriseLifecycleOptions{profile: "standalone"})

	// An Authenticode deployment, or none recorded, is not refused.
	for _, trust := range []string{"authenticode", ""} {
		recorded = trust
		accepted(t, "ensure", &windowsEnterpriseLifecycleOptions{profile: "standalone"})
		accepted(t, "ensure", &windowsEnterpriseLifecycleOptions{configPath: authenticode})
	}
}

// A certification-scope run (--state-root) takes the installed config and
// the recorded trust from its own state root, like the installer's layout,
// never from the production deployment on the same host.
func TestWindowsEnterpriseCertificationScopeUsesItsOwnInstalledTrust(t *testing.T) {
	stubWindowsEnterpriseDeployments(t, nil)
	productionTrust := "hash_pinned"
	stubWindowsEnterpriseRecordedTrust(t, &productionTrust)
	productionSigner := strings.Repeat("ab", 32)
	production := writeWindowsEnterpriseTrustConfig(t, t.TempDir(), "config.yaml",
		"  trust:\n    mode: authenticode\n    allowed_signers: ["+productionSigner+"]\n")
	windowsEnterpriseInstalledConfigPath = func() (string, error) { return production, nil }

	stateRoot := t.TempDir()
	scopeMetadata := filepath.Join(stateRoot, "install", "deployment.json")
	scopeTrust := ""
	var inspected []string
	originalScoped := windowsEnterpriseScopedDeploymentInspector
	windowsEnterpriseScopedDeploymentInspector = func(profile, path string) (winpath.EnterpriseDeployment, error) {
		inspected = append(inspected, path)
		return winpath.EnterpriseDeployment{
			Profile: profile, State: winpath.EnterpriseDeploymentInstalled, MetadataPath: path, TrustMode: scopeTrust,
		}, nil
	}
	t.Cleanup(func() { windowsEnterpriseScopedDeploymentInspector = originalScoped })
	scope := func(opts windowsEnterpriseLifecycleOptions) *windowsEnterpriseLifecycleOptions {
		opts.profile = "standalone"
		opts.installRoot = `C:\Program Files\Cisco\DefenseClaw-Cert\0123456789`
		opts.stateRoot = stateRoot
		opts.gatewayServiceName = "DefenseClawCertGateway_0123456789"
		opts.guardianServiceName = "DefenseClawCertGuardian_0123456789"
		return &opts
	}

	// With no config of its own, the scope takes neither the production
	// signer pin nor its authenticode mode.
	unsigned := scope(windowsEnterpriseLifecycleOptions{trustMode: "hash_pinned", payloadManifest: `C:\stage\payload-trust.json`})
	if err := resolveWindowsEnterpriseLifecycleProfile("ensure", unsigned); err != nil || len(unsigned.allowedSigners) != 0 {
		t.Fatalf("scope without its own config: signers %q, %v", unsigned.allowedSigners, err)
	}

	// The scope's own installed config applies, and its own metadata is the
	// recorded trust.
	scopeSigner := strings.Repeat("cd", 32)
	if err := os.MkdirAll(filepath.Join(stateRoot, "etc"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeWindowsEnterpriseTrustConfig(t, filepath.Join(stateRoot, "etc"), "config.yaml",
		"  trust:\n    mode: authenticode\n    allowed_signers: ["+scopeSigner+"]\n")
	signed := scope(windowsEnterpriseLifecycleOptions{})
	if err := resolveWindowsEnterpriseLifecycleProfile("ensure", signed); err != nil {
		t.Fatalf("scope with its own authenticode config over a hash_pinned production deployment: %v", err)
	}
	if !reflect.DeepEqual(signed.allowedSigners, []string{scopeSigner}) {
		t.Fatalf("scope signers %q, want its own %q", signed.allowedSigners, scopeSigner)
	}
	if len(inspected) == 0 || inspected[len(inspected)-1] != scopeMetadata {
		t.Fatalf("recorded trust read from %q, want %s", inspected, scopeMetadata)
	}
	scopeTrust = "hash_pinned"
	err := resolveWindowsEnterpriseLifecycleProfile("ensure", scope(windowsEnterpriseLifecycleOptions{}))
	if err == nil || !errors.Is(err, errWindowsEnterpriseInvalidArguments) || !strings.Contains(err.Error(), scopeMetadata) {
		t.Fatalf("scope with a hash_pinned record: %v", err)
	}
}
