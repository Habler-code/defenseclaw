//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// trustedOwner reports whether uid may own machine policy files and their
// ancestors. Tests replace it to model root ownership inside a temp tree.
var trustedOwner = func(uid uint32) bool { return uid == 0 }

// platformPath maps macOS's /etc, /var and /tmp compatibility symlinks to
// their /private targets so the no-symlink ancestor walk sees real
// directories. Other platforms and rooted test trees are unchanged.
func platformPath(opts Options, path string) string {
	if opts.goos() != "darwin" || opts.Root != "" {
		return path
	}
	for _, prefix := range []string{"/etc/", "/var/", "/tmp/"} {
		if strings.HasPrefix(path, prefix) {
			return "/private" + path
		}
	}
	return path
}

func validateTrustedElement(path string, wantDir bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: symlinks are not allowed in machine policy paths", path)
	}
	if wantDir && !info.IsDir() {
		return fmt.Errorf("%s: expected a directory", path)
	}
	if !wantDir && !info.Mode().IsRegular() {
		return fmt.Errorf("%s: expected a regular file", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s: group/other-writable mode %04o is not trusted for machine policy", path, info.Mode().Perm())
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot inspect owner", path)
	}
	if !trustedOwner(st.Uid) {
		return fmt.Errorf("%s: owner uid %d is not an administrator", path, st.Uid)
	}
	return nil
}

// validateTrustedAncestors checks every existing ancestor of path.
func validateTrustedAncestors(opts Options, path string) error {
	stop := "/"
	if opts.Root != "" {
		stop = filepath.Clean(opts.Root)
	}
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		if _, err := os.Lstat(dir); err == nil {
			if err := validateTrustedElement(dir, true); err != nil {
				return err
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if dir == stop || dir == filepath.Dir(dir) {
			return nil
		}
	}
}

func validateTrustedPolicyFile(opts Options, path string) error {
	if err := validateTrustedElement(path, false); err != nil {
		return err
	}
	return validateTrustedAncestors(opts, path)
}

func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}

// ensurePolicyDir creates missing directories 0755 and administrator-owned.
func ensurePolicyDir(opts Options, dir string) ([]string, error) {
	var missing []string
	for cur := dir; ; cur = filepath.Dir(cur) {
		if _, err := os.Lstat(cur); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		missing = append([]string{cur}, missing...)
		if cur == filepath.Dir(cur) || (opts.Root != "" && cur == filepath.Clean(opts.Root)) {
			break
		}
	}
	if !opts.SkipTrustChecks {
		if err := validateTrustedAncestors(opts, filepath.Join(dir, "x")); err != nil {
			return nil, err
		}
	}
	created := []string{}
	for _, cur := range missing {
		if err := os.Mkdir(cur, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
			return created, err
		}
		if err := os.Chmod(cur, 0o755); err != nil {
			return created, err
		}
		if os.Geteuid() == 0 {
			if err := os.Lchown(cur, 0, 0); err != nil {
				return created, err
			}
		}
		created = append(created, cur)
	}
	return created, nil
}

// reclaimPolicyDirs, clearPolicyFileName and displaceUntrustedPolicyFiles
// are Windows-only: every unix ancestor must already be root-owned and not
// group/other-writable, so no unprivileged user can create or occupy a
// vendor path and there is nothing to take back.
func reclaimPolicyDirs(Options, string) (policyTakeBack, error) { return policyTakeBack{}, nil }

func clearPolicyFileName(Options, string) (string, error) { return "", nil }

func displaceUntrustedPolicyFiles(Options, string, string, *State) {}

// validatePolicyLeafDir is covered on unix by the ancestor walk, which
// already applies the strict rules to every directory.
func validatePolicyLeafDir(Options, string) error { return nil }

// atomicWrite writes data to a same-directory temporary file and renames
// it over path. public selects 0644 (vendor policy) versus 0600 (records).
func atomicWrite(_ Options, path string, data []byte, public bool) error {
	dir := filepath.Dir(path)
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".defenseclaw-"+hex.EncodeToString(suffix))
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	cleanup := func() { _ = os.Remove(tmp) }
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		cleanup()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		cleanup()
		return err
	}
	mode := os.FileMode(0o600)
	if public {
		mode = 0o644
	}
	if err := file.Chmod(mode); err != nil {
		_ = file.Close()
		cleanup()
		return err
	}
	if os.Geteuid() == 0 {
		if err := file.Chown(0, 0); err != nil {
			_ = file.Close()
			cleanup()
			return err
		}
	}
	if err := file.Close(); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		cleanup()
		return err
	}
	if handle, err := os.Open(dir); err == nil {
		_ = handle.Sync()
		_ = handle.Close()
	}
	return nil
}

// ensurePrivateDir creates the root-only ownership-record directory.
func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is not a directory", dir)
	}
	return os.Chmod(dir, 0o700)
}
