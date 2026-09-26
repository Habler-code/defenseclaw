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

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// HomeState classifies a standalone Unix target home before any mutation.
type HomeState int

const (
	// HomeAvailable is a real, trusted home the worker may reconcile.
	HomeAvailable HomeState = iota
	// HomePending is a home that does not exist yet or cannot be read
	// right now (pam_mkhomedir not run, systemd-homed or ecryptfs locked,
	// automount or NFS unavailable). The target waits; it is not a trust
	// failure and does not make the host unready.
	HomePending
	// HomeUntrusted is a trust violation: symlinked home, wrong owner,
	// group/other-writable home, or a world-writable ancestor such as /tmp.
	HomeUntrusted
)

// HomeCheck is the classification result.
type HomeCheck struct {
	State  HomeState
	Reason string
	Inode  uint64
}

// ecryptfsLockedMarkers are the files ecryptfs-utils leaves in a locked
// (unmounted) private home.
var ecryptfsLockedMarkers = []string{"Access-Your-Private-Data.desktop", ".ecryptfs"}

// CheckUnixTargetHome classifies home for uid without writing anything.
func CheckUnixTargetHome(home string, uid int) HomeCheck {
	clean := filepath.Clean(home)
	if home == "" || !filepath.IsAbs(clean) || clean == string(filepath.Separator) {
		return HomeCheck{State: HomeUntrusted, Reason: fmt.Sprintf("user home %q is not an absolute non-root path", home)}
	}
	if reason := worldWritableAncestor(clean); reason != "" {
		return HomeCheck{State: HomeUntrusted, Reason: reason}
	}
	info, err := os.Lstat(clean)
	if err != nil {
		if pendingErrno(err) {
			return HomeCheck{State: HomePending, Reason: fmt.Sprintf("user home %s is not available yet: %v", clean, err)}
		}
		return HomeCheck{State: HomeUntrusted, Reason: fmt.Sprintf("inspect user home %s: %v", clean, err)}
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return HomeCheck{State: HomeUntrusted, Reason: fmt.Sprintf("user home %s is a symlink", clean)}
	}
	if !info.IsDir() {
		return HomeCheck{State: HomeUntrusted, Reason: fmt.Sprintf("user home %s is not a directory", clean)}
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return HomeCheck{State: HomeUntrusted, Reason: fmt.Sprintf("cannot inspect user home %s owner", clean)}
	}
	if int(st.Uid) != uid {
		return HomeCheck{State: HomeUntrusted, Reason: fmt.Sprintf("user home %s owner uid=%d does not match target uid=%d", clean, st.Uid, uid)}
	}
	if info.Mode().Perm()&0o022 != 0 {
		return HomeCheck{State: HomeUntrusted, Reason: fmt.Sprintf("user home %s is group/other writable", clean)}
	}
	if lockedEcryptfsHome(clean) {
		return HomeCheck{State: HomePending, Reason: fmt.Sprintf("user home %s is a locked ecryptfs home", clean), Inode: uint64(st.Ino)}
	}
	return HomeCheck{State: HomeAvailable, Inode: uint64(st.Ino)}
}

// pendingErrno reports errors that mean "not now" rather than "unsafe":
// a missing home, a locked or unmounted filesystem, or an unreachable
// network home. A root caller seeing EACCES on an NFS root_squash home is
// also "not now" — the worker reads it with the user's credentials.
func pendingErrno(err error) bool {
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) {
		return true
	}
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	switch errno {
	case syscall.ENOENT, syscall.EACCES, syscall.EPERM, syscall.EIO, syscall.ESTALE,
		syscall.ETIMEDOUT, syscall.EHOSTDOWN, syscall.EHOSTUNREACH, syscall.ENOTCONN:
		return true
	}
	return errno == enokey
}

// PendingTargetError reports whether a worker or reconcile error came from
// a home that is merely unavailable (see pendingErrno).
func PendingTargetError(err error) bool {
	return err != nil && pendingErrno(err)
}

// worldWritableAncestor returns a reason when any ancestor of home is
// writable by everyone (e.g. /tmp), where another local user could swap
// the home out from under the guardian.
func worldWritableAncestor(home string) string {
	for dir := filepath.Dir(home); ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err != nil {
			return fmt.Sprintf("inspect user home ancestor %s: %v", dir, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Sprintf("user home ancestor %s is a symlink", dir)
		}
		if info.Mode().Perm()&0o002 != 0 {
			return fmt.Sprintf("user home ancestor %s is world-writable", dir)
		}
		if dir == filepath.Dir(dir) {
			return ""
		}
	}
}

func lockedEcryptfsHome(home string) bool {
	private, err := os.Lstat(filepath.Join(home, ".Private"))
	if err != nil || private.Mode()&os.ModeSymlink == 0 {
		return false
	}
	for _, marker := range ecryptfsLockedMarkers {
		if _, err := os.Lstat(filepath.Join(home, marker)); err != nil {
			return false
		}
	}
	return true
}
