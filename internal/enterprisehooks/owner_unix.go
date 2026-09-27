//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"
)

var errEnterpriseHooksUnsupportedWindows error

// platformInstall hands a root caller's install to the per-target worker;
// an unprivileged caller installs in-process as itself.
func platformInstall(ctx context.Context, opts InstallOptions) (InstallResult, bool, error) {
	if targetProcessEUID() != 0 {
		return InstallResult{}, false, nil
	}
	result, err := installThroughTargetWorker(ctx, opts, targetOperationInstall)
	return result, true, err
}

func platformVerify(ctx context.Context, opts InstallOptions) (InstallResult, bool, error) {
	if targetProcessEUID() != 0 {
		return InstallResult{}, false, nil
	}
	result, err := installThroughTargetWorker(ctx, opts, targetOperationVerify)
	return result, true, err
}

// Resolving watch paths reads files in the target's home, so a root caller
// gets them only from ResolveWatchPaths, which runs them in the per-target
// worker.
func platformWatchDirs(InstallOptions) ([]string, bool, error) {
	if targetProcessEUID() == 0 {
		return nil, true, errRootTargetPathOperation
	}
	return nil, false, nil
}

func platformWatchOwnedFiles(InstallOptions) (WatchOwnership, bool, error) {
	if targetProcessEUID() == 0 {
		return WatchOwnership{}, true, errRootTargetPathOperation
	}
	return WatchOwnership{}, false, nil
}

// platformResolveWatchPaths hands a root caller's watch-path resolution to
// the per-target worker; an unprivileged caller resolves them in-process.
func platformResolveWatchPaths(ctx context.Context, opts InstallOptions) (WatchPathSet, bool) {
	if targetProcessEUID() != 0 {
		return WatchPathSet{}, false
	}
	set, err := resolveWatchPathsThroughTargetWorker(ctx, opts)
	if err != nil {
		return WatchPathSet{DirsErr: err, OwnershipErr: err}, true
	}
	return set, true
}

func platformRemoveManagedPolicy(context.Context, InstallOptions) error {
	return fmt.Errorf("enterprise hooks: managed policy removal is supported only on native Windows")
}

func resolveOwner(home string, uid, gid int) (int, int, error) {
	if uid < 0 || gid < 0 {
		info, err := os.Stat(home)
		if err != nil {
			return 0, 0, fmt.Errorf("enterprise hooks: stat user home owner: %w", err)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return 0, 0, fmt.Errorf("enterprise hooks: cannot inspect user home owner")
		}
		if uid < 0 {
			uid = int(st.Uid)
		}
		if gid < 0 {
			gid = int(st.Gid)
		}
	}
	if uid == 0 {
		return 0, 0, fmt.Errorf("enterprise hooks: refusing to target uid 0")
	}
	if err := validateHomeOwner(home, uid); err != nil {
		return 0, 0, err
	}
	account, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return 0, 0, fmt.Errorf("enterprise hooks: resolve target uid %d: %w", uid, err)
	}
	accountGID, err := strconv.Atoi(account.Gid)
	if err != nil || accountGID < 0 {
		return 0, 0, fmt.Errorf("enterprise hooks: target uid %d has an invalid primary gid", uid)
	}
	if gid != accountGID {
		return 0, 0, fmt.Errorf(
			"enterprise hooks: target gid %d does not match uid %d primary gid %d",
			gid, uid, accountGID,
		)
	}
	return uid, gid, nil
}

func validateHomeOwner(home string, uid int) error {
	ok, actual := fileOwnerMatches(home, uid)
	if !ok {
		return fmt.Errorf("enterprise hooks: user home %s owner uid=%d does not match target uid=%d", home, actual, uid)
	}
	return nil
}

func fileOwnerMatches(path string, uid int) (bool, int) {
	if uid < 0 {
		return true, uid
	}
	info, err := os.Lstat(path)
	if err != nil {
		return false, -1
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, -1
	}
	return int(st.Uid) == uid, int(st.Uid)
}

// withOwnerCredentials runs fn only when this process already is the target
// user. It never changes credentials: a root caller reaches target-user code
// through the per-target worker, which has permanently become the target
// before it runs, so every path operation is checked by the kernel against
// that user's permissions and no other goroutine ever shares a borrowed
// identity.
func withOwnerCredentials(uid, gid int, fn func() error) error {
	if uid < 0 || gid < 0 {
		return fmt.Errorf("enterprise hooks: target uid and gid are required")
	}
	euid := targetProcessEUID()
	egid := os.Getegid()
	if euid == 0 {
		return errRootTargetPathOperation
	}
	if euid != uid || egid != gid {
		return fmt.Errorf("enterprise hooks: cannot drop to uid=%d gid=%d from unprivileged euid=%d egid=%d", uid, gid, euid, egid)
	}
	oldUmask := syscall.Umask(0o077)
	defer syscall.Umask(oldUmask)
	return fn()
}

// runAsTarget runs fn in this process, so on Unix it succeeds only when the
// process already is the target user. Root callers must use
// RunTargetOperation, which runs a registered operation in a worker.
func runAsTarget(target TargetCredentials, fn func() error) error {
	home, err := validateUserHome(target.UserHome)
	if err != nil {
		return err
	}
	uid, gid, err := resolveOwner(home, target.UID, target.GID)
	if err != nil {
		return err
	}
	return withOwnerCredentials(uid, gid, fn)
}

var errRootTargetPathOperation = fmt.Errorf(
	"enterprise hooks: refusing a target-user path operation in a root process; it must run in the per-target worker",
)

// requireTargetPathCredentials fails when this process is root: target-user
// paths are changed only by a process that is the target user.
func requireTargetPathCredentials() error {
	if targetProcessEUID() == 0 {
		return errRootTargetPathOperation
	}
	return nil
}

// chmodOwnedPath normalizes the mode of a target-owned path. It runs only
// with the target user's credentials, so even if the path is replaced after
// inspection the kernel refuses to change anything the user does not own.
func chmodOwnedPath(path string, mode os.FileMode) error {
	if err := requireTargetPathCredentials(); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect %s before chmod: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("enterprise hooks: refusing chmod of symlink %s", path)
	}
	const relevantMode = os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky
	if info.Mode()&relevantMode == mode&relevantMode {
		return nil
	}
	if hook := beforeTargetPathMutation; hook != nil {
		hook(path)
	}
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("enterprise hooks: chmod %s: %w", path, err)
	}
	return nil
}
