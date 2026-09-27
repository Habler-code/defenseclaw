// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// hermesBootstrapProfile lays out a Hermes 0.21.5 bootstrap install: the
// launcher in hermes\bin, the install stamp in hermes\hermes-agent and the
// leased virtual environment under hermes\installs, with no
// hermes-agent\venv.
func hermesBootstrapProfile(t *testing.T) (home, launcher string) {
	t.Helper()
	home = t.TempDir()
	root := filepath.Join(home, "AppData", "Local", "hermes")
	launcher = writePerUserAdmissionFixture(t, home, "AppData", "Local", "hermes", "bin", "hermes.exe")
	writePerUserAdmissionFixture(t, home, "AppData", "Local", "hermes", "installs", "04a441694ca8a16e",
		"environments", "401a1ded57e044b79c54bbb9cf9de7cf", "venv", "Scripts", "hermes.exe")
	stamp := filepath.Join(root, "hermes-agent", "install-stamp.json")
	if err := os.MkdirAll(filepath.Dir(stamp), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stamp, []byte(`{"schemaVersion":2,"baseVersion":"0.21.5","payload":"bootstrap"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	return home, launcher
}

func TestWindowsStandalonePerUserAdmissionSelectsTheHermesBootstrapLauncher(t *testing.T) {
	home, launcher := hermesBootstrapProfile(t)
	if got, reason := windowsStandalonePerUserManagedExecutable(home, "hermes"); got != launcher {
		t.Fatalf("hermes bootstrap install = %q (%s), want the launcher %q", got, reason, launcher)
	}
	if ok, reason := windowsStandaloneRowAdmission(home, "hermes", "0.21.5"); !ok {
		t.Fatalf("hermes 0.21.5 bootstrap install refused: %s", reason)
	}
}

func TestEnumerateWindowsStandaloneEnrollsHermesBootstrapInstalls(t *testing.T) {
	stubMachineWinGet(t, nil)
	previousStandalone := windowsEnterpriseStandaloneProcess
	windowsEnterpriseStandaloneProcess = func() bool { return true }
	t.Cleanup(func() { windowsEnterpriseStandaloneProcess = previousStandalone })
	home, _ := hermesBootstrapProfile(t)
	injectWindowsProfileList(t, map[string]string{testLocalUserSID: home})
	manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("hermes"), EnumerateOptions{})
	if err != nil {
		t.Fatalf("EnumerateWindows: %v", err)
	}
	if len(manifest.Targets) != 1 || manifest.Targets[0].AgentVersion != "0.21.5" {
		t.Fatalf("targets = %+v, want one hermes row at 0.21.5", manifest.Targets)
	}
}
