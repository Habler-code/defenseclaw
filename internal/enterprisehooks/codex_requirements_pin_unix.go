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

//go:build !windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

var (
	// codexRequirementsPinPath resolves the machine requirements file. On
	// macOS /etc is a symbolic link to /private/etc; the real path lets the
	// no-symlink trust checks validate every ancestor.
	codexRequirementsPinPath = defaultCodexRequirementsPinPath
	// codexRequirementsPinOwnerUID is the required owner of the requirements
	// directory and file (root). Tests substitute their own uid.
	codexRequirementsPinOwnerUID = 0
	// codexRequirementsPinAncestorTrust validates the directories above the
	// requirements directory. Tests replace it; temp directories are not
	// root-owned.
	codexRequirementsPinAncestorTrust = func(dir string) error {
		return managed.ValidateTrustedRuntimeDir(dir, "Codex requirements directory ancestor")
	}
)

// codexRequirementsPinTempPrefix names DefenseClaw's staging files in the
// requirements directory.
const codexRequirementsPinTempPrefix = ".requirements.toml.defenseclaw-"

func defaultCodexRequirementsPinPath() string {
	if runtime.GOOS == "darwin" {
		return "/private/etc/codex/requirements.toml"
	}
	return "/etc/codex/requirements.toml"
}

// InspectCodexRequirementsHooksPin reports whether the machine Codex
// requirements pin [features] hooks = true. It never changes the file.
func InspectCodexRequirementsHooksPin() (CodexRequirementsPinResult, error) {
	path := codexRequirementsPinPath()
	result := CodexRequirementsPinResult{Path: path, State: CodexRequirementsPinAbsent}
	dir := filepath.Dir(path)
	dirInfo, err := validateCodexRequirementsPinDir(dir)
	if err != nil || dirInfo == nil {
		return result, err
	}
	raw, info, exists, err := readCodexRequirementsPinFile(path)
	if err != nil || !exists {
		return result, err
	}
	state, err := inspectCodexRequirementsPin(raw)
	if err != nil {
		return result, fmt.Errorf("enterprise hooks: %s: %w", path, err)
	}
	result.State = state
	if state != CodexRequirementsPinAbsent {
		// A pin Codex cannot read has no effect.
		if err := requireCodexRequirementsPinReadable(dir, dirInfo, path, info); err != nil {
			return result, err
		}
	}
	return result, nil
}

// EnsureCodexRequirementsHooksPin adds DefenseClaw's [features] hooks = true
// pin to the machine Codex requirements, creating the file when it is absent
// and otherwise inserting only the DefenseClaw-owned key. An administrator
// pin is left untouched. Only root may call it.
func EnsureCodexRequirementsHooksPin() (CodexRequirementsPinResult, error) {
	path := codexRequirementsPinPath()
	result := CodexRequirementsPinResult{Path: path, State: CodexRequirementsPinAbsent}
	if err := requireCodexRequirementsPinWriter(); err != nil {
		return result, err
	}
	dir := filepath.Dir(path)
	dirInfo, err := prepareCodexRequirementsPinDir(dir)
	if err != nil {
		return result, err
	}
	err = withCodexRequirementsPinDirLock(dir, func() error {
		if err := ensureCodexRequirementsPinDirTraversable(dir, path, dirInfo); err != nil {
			return err
		}
		raw, info, exists, err := readCodexRequirementsPinFile(path)
		if err != nil {
			return err
		}
		rendered, changed, err := renderCodexRequirementsPin(raw)
		if err != nil {
			return fmt.Errorf("enterprise hooks: %s: %w", path, err)
		}
		state, err := inspectCodexRequirementsPin(rendered)
		if err != nil {
			return fmt.Errorf("enterprise hooks: %s: %w", path, err)
		}
		result.State = state
		mode := os.FileMode(0o644)
		gid := -1
		if exists {
			// The administrator's mode and group are kept, so they must already
			// let Codex, running as the signed-in user, read the file.
			if err := requireCodexRequirementsPinFileReadable(path, info); err != nil {
				return err
			}
			mode = info.Mode().Perm()
			if st, ok := info.Sys().(*syscall.Stat_t); ok {
				gid = int(st.Gid)
			}
		}
		if !changed {
			return nil
		}
		if err := writeCodexRequirementsPinFile(path, rendered, mode, gid); err != nil {
			return err
		}
		result.Changed = true
		return nil
	})
	return result, err
}

// RemoveCodexRequirementsHooksPin removes exactly the bytes DefenseClaw added
// and deletes the file when DefenseClaw created it. Administrator content,
// including an administrator's own hooks pin, is preserved. Only root may
// call it.
func RemoveCodexRequirementsHooksPin() (CodexRequirementsPinResult, error) {
	path := codexRequirementsPinPath()
	result := CodexRequirementsPinResult{Path: path, State: CodexRequirementsPinAbsent}
	if err := requireCodexRequirementsPinWriter(); err != nil {
		return result, err
	}
	dir := filepath.Dir(path)
	dirInfo, err := validateCodexRequirementsPinDir(dir)
	if err != nil || dirInfo == nil {
		return result, err
	}
	err = withCodexRequirementsPinDirLock(dir, func() error {
		raw, info, exists, err := readCodexRequirementsPinFile(path)
		if err != nil || !exists {
			return err
		}
		rendered, removeFile, changed, err := removeCodexRequirementsPin(raw)
		if err != nil {
			return fmt.Errorf("enterprise hooks: %s: %w", path, err)
		}
		if !changed {
			state, err := inspectCodexRequirementsPin(raw)
			if err == nil {
				result.State = state
			}
			return nil
		}
		result.Changed = true
		if removeFile {
			if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("enterprise hooks: remove %s: %w", path, err)
			}
			result.RemovedFile = true
			return syncCodexRequirementsPinDir(dir)
		}
		state, err := inspectCodexRequirementsPin(rendered)
		if err == nil {
			result.State = state
		}
		gid := -1
		if st, ok := info.Sys().(*syscall.Stat_t); ok {
			gid = int(st.Gid)
		}
		return writeCodexRequirementsPinFile(path, rendered, info.Mode().Perm(), gid)
	})
	return result, err
}

func requireCodexRequirementsPinWriter() error {
	if os.Geteuid() != codexRequirementsPinOwnerUID {
		return fmt.Errorf("enterprise hooks: the Codex machine requirements pin can be changed only by uid %d", codexRequirementsPinOwnerUID)
	}
	return nil
}

// validateCodexRequirementsPinDir requires a real directory owned by the
// requirements owner that group and other cannot write, below trusted
// ancestors. A missing directory is reported as a nil FileInfo, not created.
func validateCodexRequirementsPinDir(dir string) (os.FileInfo, error) {
	info, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		if err := codexRequirementsPinAncestorTrust(filepath.Dir(dir)); err != nil {
			return nil, fmt.Errorf("enterprise hooks: untrusted Codex requirements parent: %w", err)
		}
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: inspect %s: %w", dir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("enterprise hooks: %s is not a regular directory", dir)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("enterprise hooks: %s is writable by group or other (%04o)", dir, info.Mode().Perm())
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != codexRequirementsPinOwnerUID {
		return nil, fmt.Errorf("enterprise hooks: %s is not owned by uid %d", dir, codexRequirementsPinOwnerUID)
	}
	if err := codexRequirementsPinAncestorTrust(filepath.Dir(dir)); err != nil {
		return nil, fmt.Errorf("enterprise hooks: untrusted Codex requirements parent: %w", err)
	}
	return info, nil
}

// prepareCodexRequirementsPinDir validates the requirements directory and
// creates it as 0755 when it is missing. The mode is set explicitly because
// Mkdir honors the process umask, and the launchd hook guardian runs with
// umask 077: a 0700 directory would keep Codex, which runs as the signed-in
// user, from reading the requirements.
func prepareCodexRequirementsPinDir(dir string) (os.FileInfo, error) {
	info, err := validateCodexRequirementsPinDir(dir)
	if err != nil || info != nil {
		return info, err
	}
	if err := os.Mkdir(dir, 0o755); err == nil {
		if err := os.Chmod(dir, 0o755); err != nil {
			return nil, fmt.Errorf("enterprise hooks: set mode on %s: %w", dir, err)
		}
	} else if !errors.Is(err, fs.ErrExist) {
		return nil, fmt.Errorf("enterprise hooks: create %s: %w", dir, err)
	}
	info, err = validateCodexRequirementsPinDir(dir)
	if err == nil && info == nil {
		err = fmt.Errorf("enterprise hooks: %s disappeared after creation", dir)
	}
	return info, err
}

// codexRequirementsPinUsersCan reports whether users other than the owner get
// the other permission bit, or the group bit through a group other than
// root's (wheel on macOS), which no standard user belongs to.
func codexRequirementsPinUsersCan(info os.FileInfo, other, group os.FileMode) bool {
	perm := info.Mode().Perm()
	if perm&other != 0 {
		return true
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Gid != 0 && perm&group != 0
}

// requireCodexRequirementsPinReadable fails when Codex, running as the
// signed-in user, could not traverse the directory or read the file, so the
// pin would have no effect.
func requireCodexRequirementsPinReadable(dir string, dirInfo os.FileInfo, path string, info os.FileInfo) error {
	if !codexRequirementsPinUsersCan(dirInfo, 0o001, 0o010) {
		return fmt.Errorf(
			"enterprise hooks: users cannot traverse %s (%04o), so Codex, which runs as the signed-in user, cannot read %s; make the directory traversable, for example mode 0755",
			dir, dirInfo.Mode().Perm(), path,
		)
	}
	if info == nil {
		return nil
	}
	return requireCodexRequirementsPinFileReadable(path, info)
}

func requireCodexRequirementsPinFileReadable(path string, info os.FileInfo) error {
	if !codexRequirementsPinUsersCan(info, 0o004, 0o040) {
		return fmt.Errorf(
			"enterprise hooks: users cannot read %s (%04o), so Codex, which runs as the signed-in user, ignores its hooks pin; make the file readable, for example mode 0644",
			path, info.Mode().Perm(),
		)
	}
	return nil
}

// ensureCodexRequirementsPinDirTraversable makes sure Codex can reach the
// requirements file. A directory users cannot traverse is repaired to 0755
// only when it holds nothing but DefenseClaw's own requirements (as an
// earlier build left it when it created the directory under umask 077);
// otherwise the directory is the administrator's and the pin fails with
// guidance instead of changing its mode.
func ensureCodexRequirementsPinDirTraversable(dir, path string, dirInfo os.FileInfo) error {
	if codexRequirementsPinUsersCan(dirInfo, 0o001, 0o010) {
		return nil
	}
	owned, err := codexRequirementsPinDirHoldsOnlyDefenseClaw(dir, path)
	if err != nil {
		return err
	}
	if !owned {
		return requireCodexRequirementsPinReadable(dir, dirInfo, path, nil)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return fmt.Errorf("enterprise hooks: set mode on %s: %w", dir, err)
	}
	return nil
}

// codexRequirementsPinDirHoldsOnlyDefenseClaw reports whether dir contains
// nothing but a requirements file DefenseClaw created (only its own pin) and
// DefenseClaw staging files.
func codexRequirementsPinDirHoldsOnlyDefenseClaw(dir, path string) (bool, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: list %s: %w", dir, err)
	}
	for _, entry := range entries {
		switch name := entry.Name(); {
		case strings.HasPrefix(name, codexRequirementsPinTempPrefix):
			continue
		case name == filepath.Base(path):
			raw, _, exists, err := readCodexRequirementsPinFile(path)
			if err != nil {
				return false, err
			}
			if !exists {
				continue
			}
			if _, removeFile, changed, err := removeCodexRequirementsPin(raw); err != nil || !changed || !removeFile {
				return false, nil
			}
		default:
			return false, nil
		}
	}
	return true, nil
}

// readCodexRequirementsPinFile reads the requirements file without following
// a final symbolic link, refusing files that are not regular, too large, not
// owned by the requirements owner, or writable by group or other.
func readCodexRequirementsPinFile(path string) ([]byte, os.FileInfo, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, false, nil
	}
	if err != nil {
		return nil, nil, false, fmt.Errorf("enterprise hooks: inspect %s: %w", path, err)
	}
	if err := validateCodexRequirementsPinFileInfo(path, info); err != nil {
		return nil, nil, false, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, nil, false, fmt.Errorf("enterprise hooks: open %s: %w", path, err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, nil, false, fmt.Errorf("enterprise hooks: %s changed while it was inspected", path)
	}
	if err := validateCodexRequirementsPinFileInfo(path, opened); err != nil {
		return nil, nil, false, err
	}
	raw, err := io.ReadAll(io.LimitReader(file, codexRequirementsPinLimit+1))
	if err != nil {
		return nil, nil, false, fmt.Errorf("enterprise hooks: read %s: %w", path, err)
	}
	if len(raw) > codexRequirementsPinLimit {
		return nil, nil, false, fmt.Errorf("enterprise hooks: %s exceeds %d bytes", path, codexRequirementsPinLimit)
	}
	return raw, opened, true, nil
}

func validateCodexRequirementsPinFileInfo(path string, info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("enterprise hooks: %s is not a regular file", path)
	}
	if info.Size() > codexRequirementsPinLimit {
		return fmt.Errorf("enterprise hooks: %s exceeds %d bytes", path, codexRequirementsPinLimit)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("enterprise hooks: %s is writable by group or other (%04o)", path, info.Mode().Perm())
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(st.Uid) != codexRequirementsPinOwnerUID {
		return fmt.Errorf("enterprise hooks: %s is not owned by uid %d", path, codexRequirementsPinOwnerUID)
	}
	if st.Nlink != 1 {
		return fmt.Errorf("enterprise hooks: %s has %d hard links", path, st.Nlink)
	}
	return nil
}

// writeCodexRequirementsPinFile replaces path atomically with a file created
// in the same trusted directory, keeping the previous mode and group.
func writeCodexRequirementsPinFile(path string, data []byte, mode os.FileMode, gid int) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, codexRequirementsPinTempPrefix+"*")
	if err != nil {
		return fmt.Errorf("enterprise hooks: stage %s: %w", path, err)
	}
	tempPath := temp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = temp.Close()
			_ = os.Remove(tempPath)
		}
	}()
	if gid >= 0 {
		if err := temp.Chown(codexRequirementsPinOwnerUID, gid); err != nil {
			return fmt.Errorf("enterprise hooks: set owner on %s: %w", tempPath, err)
		}
	}
	if err := temp.Chmod(mode &^ 0o022); err != nil {
		return fmt.Errorf("enterprise hooks: set mode on %s: %w", tempPath, err)
	}
	if _, err := temp.Write(data); err != nil {
		return fmt.Errorf("enterprise hooks: write %s: %w", tempPath, err)
	}
	if err := temp.Sync(); err != nil {
		return fmt.Errorf("enterprise hooks: sync %s: %w", tempPath, err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("enterprise hooks: close %s: %w", tempPath, err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("enterprise hooks: replace %s: %w", path, err)
	}
	committed = true
	return syncCodexRequirementsPinDir(dir)
}

func syncCodexRequirementsPinDir(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("enterprise hooks: open %s: %w", dir, err)
	}
	defer handle.Close()
	if err := handle.Sync(); err != nil && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOTSUP) {
		return fmt.Errorf("enterprise hooks: sync %s: %w", dir, err)
	}
	return nil
}

// withCodexRequirementsPinDirLock serializes DefenseClaw writers (guardian
// reconcile and uninstall) with an advisory lock on the directory itself, so
// no lock file is added to the administrator's directory.
func withCodexRequirementsPinDirLock(dir string, fn func() error) error {
	handle, err := os.OpenFile(dir, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return fmt.Errorf("enterprise hooks: open %s: %w", dir, err)
	}
	defer handle.Close()
	if err := syscall.Flock(int(handle.Fd()), syscall.LOCK_EX); err != nil {
		return fmt.Errorf("enterprise hooks: lock %s: %w", dir, err)
	}
	defer func() { _ = syscall.Flock(int(handle.Fd()), syscall.LOCK_UN) }()
	return fn()
}
