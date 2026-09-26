//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"fmt"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"golang.org/x/sys/unix"
)

// macOS has no parent-death signal; the guardian's timeout kills the
// worker's process group instead.
func targetWorkerSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

// defaultTargetWorkerExecutable returns the guardian's own image. The worker
// starts as root, so a root guardian requires that no other user can replace
// that file or any directory above it.
func defaultTargetWorkerExecutable() (string, string, error) {
	executable, err := defaultTargetWorkerExecutableFromPath()
	if err != nil {
		return "", "", err
	}
	if targetProcessEUID() == 0 {
		if err := managed.ValidateTrustedFilePath(executable, "enterprise target worker executable"); err != nil {
			return "", "", fmt.Errorf("enterprise hooks: %w", err)
		}
	}
	return executable, executable, nil
}

// hardenTargetWorkerProcess refuses debugger attachment. The credential
// change already marks the process as set-id, which denies task-port and
// ptrace access to the target user.
func hardenTargetWorkerProcess(int) error {
	if err := unix.PtraceDenyAttach(); err != nil {
		return fmt.Errorf("deny debugger attach: %w", err)
	}
	return nil
}

// setuid/setgid from root replace the saved ids as well; dropToTargetCredentials
// proves it by failing to regain uid 0.
func verifySavedTargetIDs(int, int) error { return nil }
