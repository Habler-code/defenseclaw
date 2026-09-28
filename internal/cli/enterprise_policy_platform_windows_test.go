// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// WIN-F36: an elevated administrator's `enterprise policy show|verify` on a
// standalone managed host reads the managed deployment's config, not the
// administrator's own profile.
func TestEnterprisePolicyPinsTheManagedDeploymentForAnAdministrator(t *testing.T) {
	withAuditExportManagedSeams(t, true, true)
	if err := pinStandaloneManagedEnv(); err != nil {
		t.Fatalf("pin: %v", err)
	}
	for key, want := range map[string]string{
		"DEFENSECLAW_HOME":           `C:\ProgramData\Cisco\DefenseClaw\runtime`,
		managed.ConfigPathEnv:        `C:\ProgramData\Cisco\DefenseClaw\etc\config.yaml`,
		managed.DeploymentModeEnv:    "managed_enterprise",
		managed.EnterpriseProfileEnv: managed.ProfileStandalone,
	} {
		if got := os.Getenv(key); got != want {
			t.Fatalf("%s = %q, want %q", key, got, want)
		}
	}
}

func TestEnterprisePolicyManagedEnvironmentRefusesAStandardAccount(t *testing.T) {
	withAuditExportManagedSeams(t, true, false)
	err := pinStandaloneManagedEnv()
	if err == nil || !strings.HasPrefix(err.Error(), "enterprise policy: ") ||
		!strings.Contains(err.Error(), "elevated Administrator prompt") {
		t.Fatalf("standard account error = %v, want the enterprise policy elevated-prompt guidance", err)
	}
	if got := os.Getenv(managed.ConfigPathEnv); got != "" {
		t.Fatalf("a refused policy command set %s=%q", managed.ConfigPathEnv, got)
	}
}

func TestEnterprisePolicyManagedEnvironmentLeavesExplicitAndUnmanagedHostsAlone(t *testing.T) {
	withAuditExportManagedSeams(t, true, true)
	t.Setenv(managed.ConfigPathEnv, `D:\operator\config.yaml`)
	if err := pinStandaloneManagedEnv(); err != nil {
		t.Fatalf("explicit config: %v", err)
	}
	if got := os.Getenv("DEFENSECLAW_HOME"); got != "" {
		t.Fatalf("explicit DEFENSECLAW_CONFIG was overridden: DEFENSECLAW_HOME=%q", got)
	}
	withAuditExportManagedSeams(t, false, true)
	if err := pinStandaloneManagedEnv(); err != nil {
		t.Fatalf("unmanaged host: %v", err)
	}
	if got := os.Getenv(managed.ConfigPathEnv); got != "" {
		t.Fatalf("unmanaged host got %s=%q", managed.ConfigPathEnv, got)
	}
}
