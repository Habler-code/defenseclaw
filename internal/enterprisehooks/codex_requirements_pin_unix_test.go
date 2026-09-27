// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

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
	lockDir := filepath.Join(root, "run")
	if err := os.Mkdir(lockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	originalPath := codexRequirementsPinPath
	originalUID := codexRequirementsPinOwnerUID
	originalTrust := codexRequirementsPinAncestorTrust
	originalLockPath := codexRequirementsPinLockPath
	originalLockWait := codexRequirementsPinLockWait
	codexRequirementsPinPath = func() string { return path }
	codexRequirementsPinOwnerUID = os.Geteuid()
	codexRequirementsPinAncestorTrust = func(string) error { return nil }
	codexRequirementsPinLockPath = func() string { return filepath.Join(lockDir, "codex-requirements.lock") }
	t.Cleanup(func() {
		codexRequirementsPinPath = originalPath
		codexRequirementsPinOwnerUID = originalUID
		codexRequirementsPinAncestorTrust = originalTrust
		codexRequirementsPinLockPath = originalLockPath
		codexRequirementsPinLockWait = originalLockWait
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
		if lock := defaultCodexRequirementsPinLockPath(); filepath.Dir(lock) != "/private/var/db" {
			t.Fatalf("darwin lock path = %q", lock)
		}
		if err := managed.ValidateTrustedRuntimeDir("/private/var/db", "test"); err != nil {
			t.Fatalf("/private/var/db is not a trusted lock directory: %v", err)
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

// Any user who can open the requirements directory can flock it. Such a lock
// must not stall the guardian or the uninstaller, and DefenseClaw's own lock
// must not add a file to the administrator's directory.
func TestCodexRequirementsPinIgnoresLocksOnTheRequirementsDirectory(t *testing.T) {
	dir, _ := codexPinTestLayout(t)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	holder, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		if _, err := EnsureCodexRequirementsHooksPin(); err != nil {
			done <- err
			return
		}
		_, err := RemoveCodexRequirementsHooksPin()
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a lock another process holds on the requirements directory blocked the pin")
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("files left in the requirements directory: %v", entries)
	}
	if _, err := os.Lstat(codexRequirementsPinLockPath()); !os.IsNotExist(err) {
		t.Fatalf("lock file left behind: %v", err)
	}
}

// A writer that cannot get DefenseClaw's lock fails after a bounded wait and
// changes nothing.
func TestCodexRequirementsPinLockWaitIsBounded(t *testing.T) {
	dir, _ := codexPinTestLayout(t)
	codexRequirementsPinLockWait = 200 * time.Millisecond
	holder, err := os.OpenFile(codexRequirementsPinLockPath(), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := EnsureCodexRequirementsHooksPin(); err == nil || !strings.Contains(err.Error(), "held") {
		t.Fatalf("ensure while the lock is held = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("lock wait took %s", elapsed)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("ensure changed the requirements without the lock: %v", err)
	}
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if result, err := EnsureCodexRequirementsHooksPin(); err != nil || !result.Changed {
		t.Fatalf("ensure after the lock was released = %+v, %v", result, err)
	}
}

// The pin applies the connector's ACL check to the requirements directory and
// file, so it never publishes or reports a pin the connector would reject.
func TestCodexRequirementsPinAppliesTheACLCheck(t *testing.T) {
	for _, target := range []string{"directory", "file"} {
		t.Run(target, func(t *testing.T) {
			dir, path := codexPinTestLayout(t)
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			original := []byte("[features]\nhooks = true\n")
			if err := os.WriteFile(path, original, 0o644); err != nil {
				t.Fatal(err)
			}
			refused := map[string]string{"directory": dir, "file": path}[target]
			originalACL := codexRequirementsPinACLTrust
			t.Cleanup(func() { codexRequirementsPinACLTrust = originalACL })
			codexRequirementsPinACLTrust = func(candidate string) error {
				if candidate == refused {
					return errors.New(candidate + " has write-capable macOS ACL entry")
				}
				return nil
			}
			for name, run := range map[string]func() (CodexRequirementsPinResult, error){
				"inspect": InspectCodexRequirementsHooksPin,
				"ensure":  EnsureCodexRequirementsHooksPin,
				"remove":  RemoveCodexRequirementsHooksPin,
			} {
				if _, err := run(); err == nil || !strings.Contains(err.Error(), "ACL") {
					t.Fatalf("%s with a write-capable %s ACL = %v", name, target, err)
				}
			}
			if data, _ := os.ReadFile(path); !bytes.Equal(data, original) {
				t.Fatalf("requirements changed: %q", data)
			}
		})
	}
}

// MDM and configuration-management tools rewrite the requirements without
// DefenseClaw's lock. A write that lands between DefenseClaw's read and its
// replace must be re-read, never replaced with stale content or deleted.
func TestCodexRequirementsPinKeepsConcurrentAdministratorUpdates(t *testing.T) {
	dir, path := codexPinTestLayout(t)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	original := codexRequirementsPinBeforeReplace
	t.Cleanup(func() { codexRequirementsPinBeforeReplace = original })
	replace := func(content string) {
		staged := filepath.Join(dir, "mdm.staging")
		if err := os.WriteFile(staged, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(staged, path); err != nil {
			t.Fatal(err)
		}
	}
	replace("[features]\nweb_search = true\n")

	const update = "# fleet v2\n[features]\nweb_search = false\n"
	calls := 0
	codexRequirementsPinBeforeReplace = func() {
		if calls++; calls == 1 {
			replace(update)
		}
	}
	if result, err := EnsureCodexRequirementsHooksPin(); err != nil || !result.Changed {
		t.Fatalf("ensure = %+v, %v", result, err)
	}
	merged, _ := os.ReadFile(path)
	if !bytes.HasPrefix(merged, []byte("# fleet v2\n[features]\nhooks = true "+codexRequirementsPinLineMarker+"\n")) {
		t.Fatalf("the concurrent update was replaced:\n%s", merged)
	}

	// A writer that keeps changing the file makes the pass fail unchanged.
	replace("[features]\nweb_search = true\n")
	codexRequirementsPinBeforeReplace = func() {
		calls++
		replace("# revision " + strings.Repeat("x", calls) + "\n")
	}
	if _, err := EnsureCodexRequirementsHooksPin(); !errors.Is(err, errCodexRequirementsPinChanged) {
		t.Fatalf("ensure under a persistent writer = %v", err)
	}
	if data, _ := os.ReadFile(path); !bytes.HasPrefix(data, []byte("# revision ")) {
		t.Fatalf("the persistent writer's content was replaced: %q", data)
	}

	// Remove must not delete a DefenseClaw-created file an administrator
	// replaced after it was read.
	owned, _, err := renderCodexRequirementsPin(nil)
	if err != nil {
		t.Fatal(err)
	}
	replace(string(owned))
	const adminFile = "[features]\nhooks = true\n"
	calls = 0
	codexRequirementsPinBeforeReplace = func() {
		if calls++; calls == 1 {
			replace(adminFile)
		}
	}
	if result, err := RemoveCodexRequirementsHooksPin(); err != nil || result.RemovedFile || result.State != CodexRequirementsPinAdministrator {
		t.Fatalf("remove = %+v, %v", result, err)
	}
	if data, _ := os.ReadFile(path); string(data) != adminFile {
		t.Fatalf("the administrator's replacement was removed: %q", data)
	}
}

// A region whose BEGIN marker was deleted still pins hooks on. Removal must
// fail with guidance, so the uninstaller warns, instead of reporting an
// administrator pin and leaving Codex hooks forced on.
func TestCodexRequirementsPinFileReportsRegionWithoutBeginMarker(t *testing.T) {
	dir, path := codexPinTestLayout(t)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("model = \"o5\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if result, err := EnsureCodexRequirementsHooksPin(); err != nil || !result.Changed {
		t.Fatalf("ensure = %+v, %v", result, err)
	}
	rendered, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	edited := bytes.Replace(rendered, []byte(codexRequirementsPinRegionBegin+"\n"), nil, 1)
	if bytes.Equal(edited, rendered) {
		t.Fatalf("rendered requirements have no region:\n%s", rendered)
	}
	if err := os.WriteFile(path, edited, 0o644); err != nil {
		t.Fatal(err)
	}
	if result, err := InspectCodexRequirementsHooksPin(); err != nil || result.State != CodexRequirementsPinOwned {
		t.Fatalf("inspect = %+v, %v; want owned", result, err)
	}
	result, err := RemoveCodexRequirementsHooksPin()
	if !errors.Is(err, errCodexRequirementsPinUnremovable) || result.Changed || result.RemovedFile {
		t.Fatalf("remove = %+v, %v; want the manual-removal guidance", result, err)
	}
	if data, _ := os.ReadFile(path); !bytes.Equal(data, edited) {
		t.Fatalf("failed removal changed the requirements: %q", data)
	}
}
