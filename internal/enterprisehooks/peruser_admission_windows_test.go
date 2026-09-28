// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePerUserAdmissionFixture(t *testing.T, home string, parts ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{home}, parts...)...)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("image"), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestWindowsStandalonePerUserAdmissionSelectsOnlyAdmissibleImages(t *testing.T) {
	home := t.TempDir()
	const ampVersion = "0.0.1785875347-gbc402f"

	if ok, reason := windowsStandalonePerUserAdmission(home, "amp", ampVersion); ok ||
		!strings.Contains(reason, "amp.exe") {
		t.Fatalf("amp without a native image: ok=%v reason=%q", ok, reason)
	}
	amp := writePerUserAdmissionFixture(t, home, windowsStandaloneManagedExecutableRelative["amp"][0]...)
	if ok, reason := windowsStandalonePerUserAdmission(home, "amp", ampVersion); !ok {
		t.Fatalf("amp with its native npm image refused: %s", reason)
	}
	if got, _ := windowsStandalonePerUserManagedExecutable(home, "amp"); got != amp {
		t.Fatalf("amp executable = %q, want %q", got, amp)
	}
	if ok, reason := windowsStandalonePerUserAdmission(home, "amp", "not-a-version"); ok ||
		!strings.Contains(reason, "known hook contract") {
		t.Fatalf("amp with unknown version: ok=%v reason=%q", ok, reason)
	}

	// npm OpenCode is admitted only when the opencode-ai package identity
	// checks out; the SST WinGet image wins when both exist.
	npmOpenCode := writePerUserAdmissionFixture(t, home, "AppData", "Roaming", "npm", "node_modules", "opencode-ai", "bin", "opencode.exe")
	if _, reason := windowsStandalonePerUserManagedExecutable(home, "opencode"); !strings.Contains(reason, "opencode-ai") {
		t.Fatalf("npm OpenCode without its package.json: reason = %q", reason)
	}
	manifest := filepath.Join(filepath.Dir(filepath.Dir(npmOpenCode)), "package.json")
	if err := os.WriteFile(manifest, []byte(`{"name":"not-opencode"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, _ := windowsStandalonePerUserManagedExecutable(home, "opencode"); got != "" {
		t.Fatalf("npm OpenCode with a foreign package name was admitted: %q", got)
	}
	if err := os.WriteFile(manifest, []byte(`{"name":"opencode-ai","version":"1.18.32"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if got, reason := windowsStandalonePerUserManagedExecutable(home, "opencode"); got != npmOpenCode {
		t.Fatalf("npm OpenCode = %q (%s), want %q", got, reason, npmOpenCode)
	}
	winget := writePerUserAdmissionFixture(t, home, windowsStandaloneManagedExecutableRelative["opencode"][0]...)
	if got, _ := windowsStandalonePerUserManagedExecutable(home, "opencode"); got != winget {
		t.Fatalf("OpenCode with both installs = %q, want the WinGet image %q", got, winget)
	}

	// Hermes binds to the updater-managed image inside the target profile.
	if _, reason := windowsStandalonePerUserManagedExecutable(home, "hermes"); !strings.Contains(reason, "not present") {
		t.Fatalf("hermes without its image: reason = %q", reason)
	}
	hermes := writePerUserAdmissionFixture(t, home, "AppData", "Local", "hermes", "hermes-agent", "venv", "Scripts", "hermes.exe")
	if got, reason := windowsStandalonePerUserManagedExecutable(home, "hermes"); got != hermes {
		t.Fatalf("hermes = %q (%s), want %q", got, reason, hermes)
	}
	// WIN-F27: an image this token cannot read (a folder on its path left
	// with an older release's owner-only permissions) is reported as
	// unreadable with the way forward, not as missing.
	if err := os.Remove(hermes); err != nil {
		t.Fatal(err)
	}
	previousUnreadable := windowsStandaloneExecutableUnreadable
	t.Cleanup(func() { windowsStandaloneExecutableUnreadable = previousUnreadable })
	windowsStandaloneExecutableUnreadable = func(string, error) bool { return true }
	if _, reason := windowsStandalonePerUserManagedExecutable(home, "hermes"); !strings.Contains(reason, "cannot be read as this account") ||
		!strings.Contains(reason, "LocalSystem") {
		t.Fatalf("unreadable hermes image: reason = %q", reason)
	}
	windowsStandaloneExecutableUnreadable = previousUnreadable

	// Connectors without protected executable admission need no image.
	if exe, reason := windowsStandalonePerUserManagedExecutable(home, "copilot"); exe != "" || reason != "" {
		t.Fatalf("copilot selection = %q/%q, want none", exe, reason)
	}
}
