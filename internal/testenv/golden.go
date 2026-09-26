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

package testenv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// UpdateSecureClientGoldenEnv regenerates the Secure Client golden fixtures
// under testdata/secure_client_golden instead of comparing against them.
// Regenerate only when a Secure Client behavior change is intended and
// reviewed; see testdata/secure_client_golden/README.md.
const UpdateSecureClientGoldenEnv = "DEFENSECLAW_UPDATE_SECURE_CLIENT_GOLDEN"

// SecureClientGoldenPath resolves a file in the repository's
// testdata/secure_client_golden directory from any package directory.
func SecureClientGoldenPath(t testing.TB, name string) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("golden: working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "testdata", "secure_client_golden", filepath.FromSlash(name))
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("golden: go.mod not found above the test working directory")
		}
		dir = parent
	}
}

// GoldenPlatformClass is the platform key for goldens whose Secure Client
// behavior differs by operating system.
func GoldenPlatformClass() string {
	return runtime.GOOS
}

// SkipUnlessSecureClientPlatform skips platform-keyed Secure Client goldens
// on operating systems that have no Secure Client distribution. Production
// Secure Client ships for native Windows and macOS only; Linux managed mode
// is free to change.
func SkipUnlessSecureClientPlatform(t testing.TB) {
	t.Helper()
	switch runtime.GOOS {
	case "windows", "darwin":
	default:
		t.Skipf("%s has no Secure Client distribution; platform-keyed Secure Client goldens cover windows and darwin", runtime.GOOS)
	}
}

func updatingSecureClientGolden() bool {
	return os.Getenv(UpdateSecureClientGoldenEnv) == "1"
}

// CompareSecureClientGoldenBytes compares got with the named golden file
// byte for byte, or rewrites the golden when the update switch is set.
func CompareSecureClientGoldenBytes(t testing.TB, name string, got []byte) {
	t.Helper()
	path := SecureClientGoldenPath(t, name)
	if updatingSecureClientGolden() {
		writeSecureClientGolden(t, path, got)
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("golden %s: %v (regenerate with %s=1)", name, err, UpdateSecureClientGoldenEnv)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("%s", secureClientGoldenDiff(t, name, want, got))
	}
}

// CompareSecureClientGoldenJSON marshals value deterministically and
// compares it with the named golden file.
func CompareSecureClientGoldenJSON(t testing.TB, name string, value any) {
	t.Helper()
	CompareSecureClientGoldenBytes(t, name, marshalSecureClientGolden(t, value))
}

// CompareSecureClientGoldenJSONForPlatform compares value with the entry for
// GoldenPlatformClass() in a golden file keyed by platform class. Updating
// rewrites only the current platform's entry and preserves the others, so
// each class is regenerated on its own platform.
func CompareSecureClientGoldenJSONForPlatform(t testing.TB, name string, value any) {
	t.Helper()
	class := GoldenPlatformClass()
	path := SecureClientGoldenPath(t, name)
	entries := map[string]json.RawMessage{}
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(raw, &entries); err != nil {
			t.Fatalf("golden %s: parse: %v", name, err)
		}
	case os.IsNotExist(err) && updatingSecureClientGolden():
	default:
		t.Fatalf("golden %s: %v (regenerate with %s=1)", name, err, UpdateSecureClientGoldenEnv)
	}
	got := marshalSecureClientGolden(t, value)
	if updatingSecureClientGolden() {
		entries[class] = json.RawMessage(bytes.TrimSpace(got))
		writeSecureClientGolden(t, path, marshalSecureClientGolden(t, entries))
		return
	}
	want, ok := entries[class]
	if !ok {
		t.Fatalf("golden %s has no %q entry; regenerate on that platform with %s=1", name, class, UpdateSecureClientGoldenEnv)
	}
	wantCanonical := marshalSecureClientGolden(t, want)
	if !bytes.Equal(wantCanonical, got) {
		t.Fatalf("%s", secureClientGoldenDiff(t, name+"["+class+"]", wantCanonical, got))
	}
}

// marshalSecureClientGolden renders value as canonical JSON: it round-trips
// through a generic decode so object keys are sorted regardless of whether
// the value was a struct, a map, or a raw golden entry.
func marshalSecureClientGolden(t testing.TB, value any) []byte {
	t.Helper()
	raw, ok := value.(json.RawMessage)
	if !ok {
		var err error
		raw, err = json.Marshal(value)
		if err != nil {
			t.Fatalf("golden: marshal: %v", err)
		}
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("golden: decode: %v", err)
	}
	value = decoded
	var buf bytes.Buffer
	encoder := json.NewEncoder(&buf)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		t.Fatalf("golden: marshal: %v", err)
	}
	return buf.Bytes()
}

func writeSecureClientGolden(t testing.TB, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("golden: mkdir: %v", err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatalf("golden: write %s: %v", path, err)
	}
	t.Logf("golden: updated %s", path)
}

func secureClientGoldenDiff(t testing.TB, name string, want, got []byte) string {
	t.Helper()
	wantLines := strings.Split(string(want), "\n")
	gotLines := strings.Split(string(got), "\n")
	var diff strings.Builder
	fmt.Fprintf(&diff, "Secure Client golden drift in %s.\n", name)
	fmt.Fprintf(&diff, "Production Secure Client behavior must not change. If this change is intended,\n")
	fmt.Fprintf(&diff, "review it and regenerate with %s=1 (testdata/secure_client_golden/README.md).\n", UpdateSecureClientGoldenEnv)
	shown := 0
	for i := 0; i < len(wantLines) || i < len(gotLines); i++ {
		var w, g string
		if i < len(wantLines) {
			w = wantLines[i]
		}
		if i < len(gotLines) {
			g = gotLines[i]
		}
		if w == g {
			continue
		}
		fmt.Fprintf(&diff, "line %d:\n  - %s\n  + %s\n", i+1, w, g)
		shown++
		if shown == 20 {
			diff.WriteString("  … more differences omitted\n")
			break
		}
	}
	return diff.String()
}
