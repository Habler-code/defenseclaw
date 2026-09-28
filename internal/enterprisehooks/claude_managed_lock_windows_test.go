// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readWindowsTestClaudePolicy(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var policy map[string]interface{}
	if err := json.Unmarshal(data, &policy); err != nil {
		t.Fatal(err)
	}
	return policy
}

func writeWindowsTestClaudeManagedFile(t *testing.T, path string, value map[string]interface{}) {
	t.Helper()
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(body, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := setWindowsManagedPolicyProtection(path, false, true); err != nil {
		t.Fatal(err)
	}
}

// The machine drop-in must stop user, project, local and plugin Claude hooks
// (which can rewrite PreToolUse input) unless the administrator opts out, and
// verify must follow the configured choice.
func TestInstallWindowsClaudeManagedPolicyLocksManagedHooksOnly(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, map[string]interface{}{
		"companyAnnouncements": []interface{}{"managed by test"},
	})
	opts := windowsManagedInstallOptions(fixture)
	result, err := Install(context.Background(), opts)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if result.ClaudeManagedHooksOnly != ClaudeManagedHooksOnlyEnforced {
		t.Fatalf("install lock state = %q, want enforced", result.ClaudeManagedHooksOnly)
	}
	if policy := readWindowsTestClaudePolicy(t, fixture.policyPath); policy["allowManagedHooksOnly"] != true {
		t.Fatalf("installed policy allowManagedHooksOnly = %#v, want true", policy["allowManagedHooksOnly"])
	}
	verified, err := Verify(context.Background(), opts)
	if err != nil {
		t.Fatalf("Verify locked policy: %v", err)
	}
	if verified.ClaudeManagedHooksOnly != ClaudeManagedHooksOnlyEnforced {
		t.Fatalf("verify lock state = %q, want enforced", verified.ClaudeManagedHooksOnly)
	}

	optOut := opts
	optOut.ClaudeCodeAllowUnmanagedHooks = true
	if _, err := Verify(context.Background(), optOut); err == nil ||
		!strings.Contains(err.Error(), "differs from the canonical") {
		t.Fatalf("Verify after config opt-out against a locked policy = %v, want drift", err)
	}
	if _, err := Install(context.Background(), optOut); err != nil {
		t.Fatalf("Install with opt-out: %v", err)
	}
	if _, exists := readWindowsTestClaudePolicy(t, fixture.policyPath)["allowManagedHooksOnly"]; exists {
		t.Fatal("opted-out policy still sets allowManagedHooksOnly")
	}
	verified, err = Verify(context.Background(), optOut)
	if err != nil {
		t.Fatalf("Verify opted-out policy: %v", err)
	}
	if verified.ClaudeManagedHooksOnly != ClaudeManagedHooksOnlyDisabledByAdmin {
		t.Fatalf("verify lock state = %q, want disabled_by_admin", verified.ClaudeManagedHooksOnly)
	}
	if _, err := Verify(context.Background(), opts); err == nil ||
		!strings.Contains(err.Error(), "differs from the canonical") {
		t.Fatalf("Verify of an unlocked policy under the default config = %v, want drift", err)
	}
}

func TestInstallWindowsClaudeRejectsManagedSettingsThatDisableTheLock(t *testing.T) {
	for name, target := range map[string]func(fixture windowsManagedInstallFixture) string{
		"later drop-in": func(fixture windowsManagedInstallFixture) string {
			return filepath.Join(filepath.Dir(fixture.policyPath), "99-other.json")
		},
		"base managed settings": func(fixture windowsManagedInstallFixture) string {
			return filepath.Join(filepath.Dir(filepath.Dir(fixture.policyPath)), "managed-settings.json")
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newWindowsManagedInstallFixture(t, nil)
			conflict := target(fixture)
			writeWindowsTestClaudeManagedFile(t, conflict, map[string]interface{}{"allowManagedHooksOnly": false})
			opts := windowsManagedInstallOptions(fixture)
			_, err := Install(context.Background(), opts)
			if err == nil || !strings.Contains(err.Error(), "allowManagedHooksOnly=false") ||
				!strings.Contains(err.Error(), conflict) {
				t.Fatalf("Install with conflicting %s = %v", name, err)
			}
			if _, statErr := os.Lstat(fixture.policyPath); !os.IsNotExist(statErr) {
				t.Fatalf("conflicting install wrote the drop-in: %v", statErr)
			}
			opts.ClaudeCodeAllowUnmanagedHooks = true
			if _, err := Install(context.Background(), opts); err != nil {
				t.Fatalf("Install with explicit opt-out: %v", err)
			}
			if _, err := Verify(context.Background(), opts); err != nil {
				t.Fatalf("Verify with explicit opt-out: %v", err)
			}
			opts.ClaudeCodeAllowUnmanagedHooks = false
			if _, err := Verify(context.Background(), opts); err == nil {
				t.Fatal("Verify accepted a lock that another managed file disables")
			}
		})
	}
}

func TestInstallWindowsClaudeRejectsLaterDropInThatDisablesAllHooks(t *testing.T) {
	fixture := newWindowsManagedInstallFixture(t, nil)
	opts := windowsManagedInstallOptions(fixture)
	if _, err := Install(context.Background(), opts); err != nil {
		t.Fatalf("Install: %v", err)
	}
	later := filepath.Join(filepath.Dir(fixture.policyPath), "99-other.json")
	writeWindowsTestClaudeManagedFile(t, later, map[string]interface{}{"disableAllHooks": true})
	if _, err := Verify(context.Background(), opts); err == nil ||
		!strings.Contains(err.Error(), "disable") {
		t.Fatalf("Verify with a later disableAllHooks drop-in = %v, want conflict", err)
	}
}
