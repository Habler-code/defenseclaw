// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func standaloneWindowsEnrollmentConfig(enrollment config.EnterpriseEnrollmentConfig) *config.Config {
	return &config.Config{
		DeploymentMode: managed.DeploymentModeManagedEnterprise,
		Enterprise: config.EnterpriseConfig{
			Profile:    managed.ProfileStandalone,
			Enrollment: enrollment,
		},
	}
}

// exempt_users must not become exclusions: an excluded SID is unregistered
// and every machine-policy hook fails closed for it.
func TestStandaloneWindowsEnumerateOptionsKeepsExemptUsersSeparate(t *testing.T) {
	cfg := standaloneWindowsEnrollmentConfig(config.EnterpriseEnrollmentConfig{
		IncludeUsers: []string{"alice"},
		ExcludeUsers: []string{"bob"},
		ExemptUsers:  []string{"breakglass"},
	})
	opts := standaloneWindowsEnumerateOptions(cfg, enterprisehooks.EnumerateOptions{})
	if strings.Join(opts.ExcludeUsers, ",") != "bob" {
		t.Fatalf("ExcludeUsers = %v, want only the excluded user", opts.ExcludeUsers)
	}
	if strings.Join(opts.ExemptUsers, ",") != "breakglass" || strings.Join(opts.IncludeUsers, ",") != "alice" {
		t.Fatalf("options = %+v, want include and exempt carried separately", opts)
	}

	secureClient := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	if got := standaloneWindowsEnumerateOptions(secureClient, enterprisehooks.EnumerateOptions{}); len(got.IncludeUsers)+len(got.ExcludeUsers)+len(got.ExemptUsers) != 0 {
		t.Fatalf("Secure Client options gained enrollment filters: %+v", got)
	}
}

func runStandaloneWindowsEnumerateCycleForTest(t *testing.T, cfg *config.Config) (string, int) {
	t.Helper()
	previousConfig := enterpriseWindowsEnumerateConfigLoader
	previousEnumerator := enterpriseWindowsEnumerateProfileEnumerator
	previousWriter := enterpriseWindowsEnumerateManifestWriter
	t.Cleanup(func() {
		enterpriseWindowsEnumerateConfigLoader = previousConfig
		enterpriseWindowsEnumerateProfileEnumerator = previousEnumerator
		enterpriseWindowsEnumerateManifestWriter = previousWriter
	})
	enterpriseWindowsEnumerateConfigLoader = func() (*config.Config, error) { return cfg, nil }
	calls := 0
	enterpriseWindowsEnumerateProfileEnumerator = func(context.Context, *config.Config, enterprisehooks.EnumerateOptions) (enterprisehooks.Manifest, error) {
		calls++
		return enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{}}, nil
	}
	enterpriseWindowsEnumerateManifestWriter = func(string, enterprisehooks.Manifest) (bool, error) {
		calls++
		return false, nil
	}
	stderr := new(bytes.Buffer)
	manifest := filepath.Join(t.TempDir(), "targets.yaml")
	if err := runEnterpriseWindowsEnumerateSingleCycle(context.Background(), stderr, manifest, true); err != nil {
		t.Fatalf("cycle: %v", err)
	}
	return stderr.String(), calls
}

// enterprise.enrollment.mode manifest hands targets.yaml to the
// administrator on Windows too: the enumerator neither walks nor publishes.
func TestEnterpriseWindowsEnumerateIdlesInManifestMode(t *testing.T) {
	log, calls := runStandaloneWindowsEnumerateCycleForTest(t, standaloneWindowsEnrollmentConfig(
		config.EnterpriseEnrollmentConfig{Mode: config.EnterpriseEnrollmentManifest},
	))
	if calls != 0 {
		t.Fatalf("manifest mode walked or published targets (%d calls)", calls)
	}
	if !strings.Contains(log, "cycle idle: enterprise.enrollment.mode is manifest") {
		t.Fatalf("idle cycle must say why; log:\n%s", log)
	}

	_, calls = runStandaloneWindowsEnumerateCycleForTest(t, standaloneWindowsEnrollmentConfig(
		config.EnterpriseEnrollmentConfig{Mode: config.EnterpriseEnrollmentAuto},
	))
	if calls != 2 {
		t.Fatalf("auto mode must enumerate and publish (%d calls)", calls)
	}
}

func TestEnterpriseWindowsEnumerateWarnsAboutGroupFilters(t *testing.T) {
	log, _ := runStandaloneWindowsEnumerateCycleForTest(t, standaloneWindowsEnrollmentConfig(
		config.EnterpriseEnrollmentConfig{ExcludeGroups: []string{"Administrators"}},
	))
	if !strings.Contains(log, "WARN enterprise.enrollment.include_groups and exclude_groups are not applied on Windows") {
		t.Fatalf("group filters must not be ignored silently; log:\n%s", log)
	}
}
