// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func codexPinTestLayout(t *testing.T) (dir, path string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	dir = filepath.Join(root, "etc", "codex")
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, "requirements.toml")
	originalPath := codexRequirementsPinPath
	originalUID := codexRequirementsPinOwnerUID
	originalTrust := codexRequirementsPinAncestorTrust
	codexRequirementsPinPath = func() string { return path }
	codexRequirementsPinOwnerUID = os.Geteuid()
	codexRequirementsPinAncestorTrust = func(string) error { return nil }
	t.Cleanup(func() {
		codexRequirementsPinPath = originalPath
		codexRequirementsPinOwnerUID = originalUID
		codexRequirementsPinAncestorTrust = originalTrust
	})
	return dir, path
}

func TestCodexRequirementsPinFileLifecycleCreatesAndRemovesOwnedFile(t *testing.T) {
	dir, path := codexPinTestLayout(t)
	if result, err := InspectCodexRequirementsHooksPin(); err != nil || result.State != CodexRequirementsPinAbsent {
		t.Fatalf("inspect before install = %+v, %v", result, err)
	}
	result, err := EnsureCodexRequirementsHooksPin()
	if err != nil || !result.Changed || result.State != CodexRequirementsPinOwned || result.Path != path {
		t.Fatalf("ensure = %+v, %v", result, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("created requirements mode = %04o, want 0644 (readable by Codex as the user)", info.Mode().Perm())
	}
	dirInfo, err := os.Stat(dir)
	if err != nil || dirInfo.Mode().Perm()&0o022 != 0 {
		t.Fatalf("created requirements directory = %v, %v", dirInfo, err)
	}
	if result, err := EnsureCodexRequirementsHooksPin(); err != nil || result.Changed {
		t.Fatalf("second ensure = %+v, %v; want idempotent", result, err)
	}
	result, err = RemoveCodexRequirementsHooksPin()
	if err != nil || !result.Changed || !result.RemovedFile {
		t.Fatalf("remove = %+v, %v", result, err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("DefenseClaw-created requirements file survived removal: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatalf("removal left files behind: %v", entries)
	}
	if result, err := RemoveCodexRequirementsHooksPin(); err != nil || result.Changed {
		t.Fatalf("second remove = %+v, %v", result, err)
	}
}

func TestCodexRequirementsPinFileMergePreservesAdministratorFile(t *testing.T) {
	dir, path := codexPinTestLayout(t)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	original := []byte("# fleet\nallowed_sandbox_modes = [\"read-only\"]\n\n[features]\nweb_search = true\n")
	if err := os.WriteFile(path, original, 0o444); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o444); err != nil {
		t.Fatal(err)
	}
	result, err := EnsureCodexRequirementsHooksPin()
	if err != nil || !result.Changed || result.State != CodexRequirementsPinOwned {
		t.Fatalf("ensure = %+v, %v", result, err)
	}
	merged, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(merged, []byte("[features]\nhooks = true "+codexRequirementsPinLineMarker+"\nweb_search = true\n")) {
		t.Fatalf("pin was not merged into the administrator [features] table:\n%s", merged)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o444 {
		t.Fatalf("merge changed the administrator file mode: %v, %v", info, err)
	}
	result, err = RemoveCodexRequirementsHooksPin()
	if err != nil || !result.Changed || result.RemovedFile {
		t.Fatalf("remove = %+v, %v", result, err)
	}
	restored, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(restored, original) {
		t.Fatalf("removal did not restore the administrator file: %q, %v", restored, err)
	}
}

func TestCodexRequirementsPinFileLeavesAdministratorPinAndReportsConflicts(t *testing.T) {
	dir, path := codexPinTestLayout(t)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	adminPin := []byte("[features]\nhooks = true\n")
	if err := os.WriteFile(path, adminPin, 0o644); err != nil {
		t.Fatal(err)
	}
	if result, err := EnsureCodexRequirementsHooksPin(); err != nil || result.Changed || result.State != CodexRequirementsPinAdministrator {
		t.Fatalf("ensure with an administrator pin = %+v, %v", result, err)
	}
	if result, err := RemoveCodexRequirementsHooksPin(); err != nil || result.Changed || result.RemovedFile {
		t.Fatalf("remove with an administrator pin = %+v, %v", result, err)
	}
	if data, _ := os.ReadFile(path); !bytes.Equal(data, adminPin) {
		t.Fatalf("administrator pin changed: %q", data)
	}

	disabling := []byte("[features]\nhooks = false\n")
	if err := os.WriteFile(path, disabling, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureCodexRequirementsHooksPin(); err == nil || !strings.Contains(err.Error(), "hooks = false") {
		t.Fatalf("ensure over a disabling requirement = %v", err)
	}
	if _, err := InspectCodexRequirementsHooksPin(); err == nil {
		t.Fatal("inspect accepted a disabling requirement")
	}
	if data, _ := os.ReadFile(path); !bytes.Equal(data, disabling) {
		t.Fatalf("conflicting administrator requirement changed: %q", data)
	}
}

func TestCodexRequirementsPinFileRefusesUntrustedObjects(t *testing.T) {
	for name, prepare := range map[string]func(t *testing.T, dir, path string){
		"symlinked file": func(t *testing.T, dir, path string) {
			target := filepath.Join(filepath.Dir(dir), "elsewhere.toml")
			if err := os.WriteFile(target, []byte("model = \"o5\"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		},
		"group-writable file": func(t *testing.T, _ string, path string) {
			if err := os.WriteFile(path, []byte("model = \"o5\"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o664); err != nil {
				t.Fatal(err)
			}
		},
		"hard-linked file": func(t *testing.T, dir, path string) {
			if err := os.WriteFile(path, []byte("model = \"o5\"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(path, filepath.Join(filepath.Dir(dir), "alias.toml")); err != nil {
				t.Fatal(err)
			}
		},
		"group-writable directory": func(t *testing.T, dir, _ string) {
			if err := os.Chmod(dir, 0o775); err != nil {
				t.Fatal(err)
			}
		},
		"oversized file": func(t *testing.T, _ string, path string) {
			if err := os.WriteFile(path, bytes.Repeat([]byte("#"), codexRequirementsPinLimit+1), 0o644); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir, path := codexPinTestLayout(t)
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			prepare(t, dir, path)
			before, _ := os.Lstat(path)
			if _, err := EnsureCodexRequirementsHooksPin(); err == nil {
				t.Fatal("ensure accepted an untrusted requirements object")
			}
			if _, err := RemoveCodexRequirementsHooksPin(); err == nil {
				t.Fatal("remove accepted an untrusted requirements object")
			}
			after, _ := os.Lstat(path)
			if before != nil && (after == nil || !os.SameFile(before, after) || after.Size() != before.Size()) {
				t.Fatal("an untrusted requirements object was modified")
			}
		})
	}
}

func TestCodexRequirementsPinRequiresTheOwnerIdentity(t *testing.T) {
	_, path := codexPinTestLayout(t)
	codexRequirementsPinOwnerUID = os.Geteuid() + 1
	if _, err := EnsureCodexRequirementsHooksPin(); err == nil {
		t.Fatal("ensure ran without the requirements owner identity")
	}
	if _, err := RemoveCodexRequirementsHooksPin(); err == nil {
		t.Fatal("remove ran without the requirements owner identity")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("requirements were created by a non-owner: %v", err)
	}
}

// macOS reaches /etc through a symbolic link; the pin addresses the real
// /private/etc path so every ancestor passes the no-symlink trust walk.
func TestCodexRequirementsPinDefaultPathHasTrustedAncestors(t *testing.T) {
	path := defaultCodexRequirementsPinPath()
	if runtime.GOOS == "darwin" {
		if path != "/private/etc/codex/requirements.toml" {
			t.Fatalf("darwin requirements path = %q", path)
		}
		if err := managed.ValidateTrustedRuntimeDir("/private/etc", "test"); err != nil {
			t.Fatalf("/private/etc is not a trusted ancestor: %v", err)
		}
		if err := managed.ValidateTrustedRuntimeDir("/etc", "test"); err == nil {
			t.Fatal("/etc unexpectedly passed the no-symlink trust walk")
		}
		return
	}
	if path != "/etc/codex/requirements.toml" {
		t.Fatalf("requirements path = %q", path)
	}
}

func codexPinTestMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

// The launchd hook guardian runs with umask 077. The directory and file it
// creates must still let Codex, which runs as the signed-in user, read the pin.
func TestCodexRequirementsPinCreatesReadableRequirementsUnderGuardianUmask(t *testing.T) {
	dir, path := codexPinTestLayout(t)
	previous := syscall.Umask(0o077)
	result, err := EnsureCodexRequirementsHooksPin()
	syscall.Umask(previous)
	if err != nil || !result.Changed || result.State != CodexRequirementsPinOwned {
		t.Fatalf("ensure under umask 077 = %+v, %v", result, err)
	}
	for target, want := range map[string]os.FileMode{dir: 0o755, path: 0o644} {
		if got := codexPinTestMode(t, target); got != want {
			t.Fatalf("%s mode = %04o, want %04o so Codex running as the user can read the pin", target, got, want)
		}
	}
	if result, err := InspectCodexRequirementsHooksPin(); err != nil || result.State != CodexRequirementsPinOwned {
		t.Fatalf("inspect = %+v, %v", result, err)
	}
}

// An earlier build created the directory as 0700. Ensure repairs a directory
// that holds only DefenseClaw's own requirements, and Inspect reports the
// unreadable pin until then.
func TestCodexRequirementsPinRepairsItsOwnUntraversableDirectory(t *testing.T) {
	dir, path := codexPinTestLayout(t)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	owned, _, err := renderCodexRequirementsPin(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, owned, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectCodexRequirementsHooksPin(); err == nil || !strings.Contains(err.Error(), "cannot traverse") {
		t.Fatalf("inspect of a pin in a 0700 directory = %v, want the traverse error", err)
	}
	if result, err := EnsureCodexRequirementsHooksPin(); err != nil || result.State != CodexRequirementsPinOwned {
		t.Fatalf("ensure = %+v, %v", result, err)
	}
	if got := codexPinTestMode(t, dir); got != 0o755 {
		t.Fatalf("DefenseClaw directory mode = %04o, want it repaired to 0755", got)
	}
	if _, err := InspectCodexRequirementsHooksPin(); err != nil {
		t.Fatalf("inspect after repair: %v", err)
	}

	// The empty directory an earlier removal left behind is repaired too.
	if _, err := RemoveCodexRequirementsHooksPin(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if result, err := EnsureCodexRequirementsHooksPin(); err != nil || !result.Changed {
		t.Fatalf("ensure over an empty 0700 directory = %+v, %v", result, err)
	}
	if got := codexPinTestMode(t, dir); got != 0o755 {
		t.Fatalf("empty DefenseClaw directory mode = %04o, want it repaired to 0755", got)
	}
}

// Administrator requirements Codex cannot read are reported, not changed.
func TestCodexRequirementsPinReportsRequirementsUsersCannotRead(t *testing.T) {
	for name, tc := range map[string]struct {
		content  string
		dirMode  os.FileMode
		fileMode os.FileMode
		inspect  bool
	}{
		"administrator pin in an untraversable directory":  {"[features]\nhooks = true\n", 0o700, 0o644, true},
		"administrator file in an untraversable directory": {"[features]\nweb_search = true\n", 0o700, 0o644, false},
		"unreadable administrator pin":                     {"[features]\nhooks = true\n", 0o755, 0o600, true},
		"unreadable administrator file":                    {"[features]\nweb_search = true\n", 0o755, 0o600, false},
	} {
		t.Run(name, func(t *testing.T) {
			dir, path := codexPinTestLayout(t)
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, tc.fileMode); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, tc.dirMode); err != nil {
				t.Fatal(err)
			}
			if _, err := EnsureCodexRequirementsHooksPin(); err == nil || !strings.Contains(err.Error(), "users cannot") {
				t.Fatalf("ensure = %v, want the users-cannot-read error", err)
			}
			if _, err := InspectCodexRequirementsHooksPin(); (err != nil) != tc.inspect {
				t.Fatalf("inspect error = %v, want error %t", err, tc.inspect)
			}
			if got := codexPinTestMode(t, dir); got != tc.dirMode {
				t.Fatalf("administrator directory mode changed to %04o", got)
			}
			if data, err := os.ReadFile(path); err != nil || string(data) != tc.content {
				t.Fatalf("administrator requirements changed: %q, %v", data, err)
			}
		})
	}
}
