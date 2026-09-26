//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadManifestWindowsRejectsNameOnlyTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	if err := os.WriteFile(path, []byte(`
version: 1
targets:
  - user: alice
    connector: codex
`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadManifest(path)
	if err == nil || !strings.Contains(err.Error(), "requires explicit user_home") {
		t.Fatalf("LoadManifest error = %v, want name-only Windows target rejection", err)
	}
}

func TestLoadManifestWindowsRejectsMissingOrServiceSID(t *testing.T) {
	tests := []struct {
		name string
		sid  string
		want string
	}{
		{name: "missing", want: "requires explicit sid"},
		{name: "local_system", sid: "S-1-5-18", want: "not an interactive user"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "targets.yaml")
			body := "version: 1\ntargets:\n  - user_home: 'C:\\\\Users\\\\alice'\n"
			if tc.sid != "" {
				body += "    sid: " + tc.sid + "\n"
			}
			body += "    connector: codex\n"
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadManifest(path)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("LoadManifest error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLoadManifestWindowsRejectsDuplicateSIDTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	if err := os.WriteFile(path, []byte(`
version: 1
targets:
  - user_home: 'C:\Users\alice'
    sid: S-1-5-21-1-2-3-1001
    connector: codex
    agent_version: codex-cli 0.142.0
  - user_home: 'C:\Profiles\renamed'
    sid: s-1-5-21-1-2-3-1001
    connector: codex
    agent_version: codex-cli 0.142.0
`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadManifest(path)
	if err == nil || !strings.Contains(err.Error(), "duplicates enabled target") {
		t.Fatalf("LoadManifest error = %v, want duplicate SID target rejection", err)
	}
}

func TestLoadManifestWindowsRejectsCanonicalSIDAliasTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	if err := os.WriteFile(path, []byte(`
version: 1
targets:
  - user_home: 'C:\Users\alice'
    sid: S-1-5-21-1-2-3-1001
    connector: codex
    agent_version: codex-cli 0.142.0
  - user_home: 'C:\Profiles\renamed'
    sid: S-1-5-021-001-002-003-01001
    connector: codex
    agent_version: codex-cli 0.142.0
`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadManifest(path)
	if err == nil || !strings.Contains(err.Error(), "duplicates enabled target") {
		t.Fatalf("LoadManifest error = %v, want canonical SID alias rejection", err)
	}
}

func TestLoadManifestWindowsRejectsMissingAgentVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	if err := os.WriteFile(path, []byte(`
version: 1
targets:
  - user_home: 'C:\Users\alice'
    sid: S-1-5-21-1-2-3-1001
    connector: codex
`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadManifest(path)
	if err == nil || !strings.Contains(err.Error(), "requires explicit agent_version") {
		t.Fatalf("LoadManifest error = %v, want explicit agent_version rejection", err)
	}
}

func TestLoadManifestWindowsAcceptsEnabledDeferredTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	if err := os.WriteFile(path, []byte(`
version: 1
targets:
  - user_home: 'C:\Users\alice'
    sid: S-1-5-21-1-2-3-1001
    connector: codex
    agent_version: codex-cli 0.142.0
    enabled: true
    deferred: true
`), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}
	if len(manifest.Targets) != 1 || !manifest.Targets[0].IsEnabled() ||
		!manifest.Targets[0].IsDeferred() {
		t.Fatalf("manifest = %+v, want one enabled deferred target", manifest)
	}
}

// legacyClaudePlaceholderManifest is shaped like a targets.yaml an earlier
// release rendered: release-26.8.4 and main before the Claude floor tracked
// the hook contracts wrote 2.1.152 as the Claude placeholder for a user with
// no detected client, and the enumerator keeps a known row's version.
const legacyClaudePlaceholderManifest = `
version: 1
targets:
  - user: "alice"
    user_home: 'C:\Users\alice'
    sid: S-1-5-21-1-2-3-1001
    connector: "claudecode"
    agent_version: "2.1.152"
    enabled: true
  - user: "alice"
    user_home: 'C:\Users\alice'
    sid: S-1-5-21-1-2-3-1001
    connector: "codex"
    agent_version: "0.131.0"
    enabled: true
  - user: "bob"
    user_home: 'C:\Users\bob'
    sid: S-1-5-21-1-2-3-1002
    connector: "claudecode"
    agent_version: "2.1.153"
    enabled: true
    deferred: true
  - user: "bob"
    user_home: 'C:\Users\bob'
    sid: S-1-5-21-1-2-3-1002
    connector: "cursor"
    enabled: false
`

// TestLoadManifestWindowsKeepsLegacyClaudeRowsLoadable is the #901 review
// regression: raising the Claude enrollment floor to the lowest hook contract
// must not make a manifest with legacy 2.1.152/2.1.153 rows unreadable, which
// failed Upgrade/Repair capture, Uninstall teardown and the enumerator's
// previous-row state for every target and connector.
func TestLoadManifestWindowsKeepsLegacyClaudeRowsLoadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	if err := os.WriteFile(path, []byte(legacyClaudePlaceholderManifest), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, err := LoadManifest(path)
	if err != nil {
		t.Fatalf("LoadManifest(legacy Claude rows) error = %v", err)
	}
	if len(manifest.Targets) != 4 {
		t.Fatalf("manifest targets = %d, want 4", len(manifest.Targets))
	}
	if _, _, err := LoadManifestWithSHA256(path); err != nil {
		t.Fatalf("LoadManifestWithSHA256(legacy Claude rows) error = %v", err)
	}

	// The enumerator reads the same file for previous-row state. A load
	// failure there treats every row as new and drops admin decisions such
	// as the disabled Cursor row.
	var logged []string
	previous := loadPreviousManifestForEnumeration(path, func(subject, reason string) {
		logged = append(logged, subject+": "+reason)
	})
	if len(logged) != 0 {
		t.Fatalf("enumerator logged %q, want the previous manifest to load", logged)
	}
	cursor, ok := previous[previousManifestKey("S-1-5-21-1-2-3-1002", "cursor")]
	if !ok || cursor.IsEnabled() {
		t.Fatalf("previous cursor row = %+v (found %t), want the disabled decision kept", cursor, ok)
	}
	if claude := previous[previousManifestKey("S-1-5-21-1-2-3-1001", "claudecode")]; claude.AgentVersion != "2.1.152" {
		t.Fatalf("previous claude row version = %q, want 2.1.152", claude.AgentVersion)
	}

	// Enrollment still refuses the legacy rows, one target at a time.
	for _, version := range []string{"2.1.152", "2.1.153"} {
		for name, gate := range map[string]func(context.Context, InstallOptions) (InstallResult, bool, error){
			"install": platformInstall,
			"verify":  platformVerify,
		} {
			_, handled, err := gate(context.Background(), InstallOptions{
				ConnectorName: "claudecode",
				AgentVersion:  version,
			})
			if !handled || err == nil ||
				!strings.Contains(err.Error(), "below the Windows enterprise minimum "+windowsEnterpriseManagedAgentMinimum("claudecode")) ||
				!strings.Contains(err.Error(), "Repair -Mode or -Manifest") {
				t.Fatalf("platform %s(claudecode %s) = handled %t, err %v; want a per-target floor refusal with the fix", name, version, handled, err)
			}
		}
	}
}

func TestLoadManifestWindowsRejectsClaudeBelowLegacyFloor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.yaml")
	if err := os.WriteFile(path, []byte(`
version: 1
targets:
  - user_home: 'C:\Users\alice'
    sid: S-1-5-21-1-2-3-1001
    connector: claudecode
    agent_version: "2.1.151"
`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadManifest(path)
	if err == nil || !strings.Contains(err.Error(), "below the Windows enterprise minimum 2.1.152") {
		t.Fatalf("LoadManifest error = %v, want the legacy manifest floor to still reject 2.1.151", err)
	}
}
