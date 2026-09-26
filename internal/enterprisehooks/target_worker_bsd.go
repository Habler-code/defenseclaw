//go:build !windows && !linux && !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"fmt"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func targetWorkerSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

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

func hardenTargetWorkerProcess(int) error { return nil }

func verifySavedTargetIDs(int, int) error { return nil }
