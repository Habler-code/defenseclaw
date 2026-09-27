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

	writePerUserAdmissionFixture(t, home, windowsStandaloneManagedExecutableRelative["amp"]...)
	if ok, reason := windowsStandalonePerUserAdmission(home, "amp", ampVersion); ok ||
		!strings.Contains(reason, "not supported") {
		t.Fatalf("amp must stay unmanaged until its plugin custody verifies: ok=%v reason=%q", ok, reason)
	}

	if ok, reason := windowsStandalonePerUserAdmission(home, "amp", "not-a-version"); ok ||
		!strings.Contains(reason, "known hook contract") {
		t.Fatalf("amp with unknown version: ok=%v reason=%q", ok, reason)
	}

	// npm OpenCode is not the admitted WinGet image.
	writePerUserAdmissionFixture(t, home, "AppData", "Roaming", "npm", "node_modules", "opencode-ai", "bin", "opencode.exe")
	if _, reason := windowsStandalonePerUserManagedExecutable(home, "opencode"); !strings.Contains(reason, "WinGet") {
		t.Fatalf("npm OpenCode reason = %q, want WinGet guidance", reason)
	}

	if _, reason := windowsStandalonePerUserManagedExecutable(home, "hermes"); !strings.Contains(reason, "not supported") {
		t.Fatalf("hermes reason = %q, want an explicit unsupported reason", reason)
	}

	// Connectors without protected executable admission need no image.
	if exe, reason := windowsStandalonePerUserManagedExecutable(home, "copilot"); exe != "" || reason != "" {
		t.Fatalf("copilot selection = %q/%q, want none", exe, reason)
	}
}
