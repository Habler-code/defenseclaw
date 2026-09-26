//go:build !windows && !linux && !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"syscall"
)

func enterpriseHookWorkerSysProcAttr(account enterpriseHookWorkerAccount) *syscall.SysProcAttr {
	attr := &syscall.SysProcAttr{Setsid: true}
	if os.Geteuid() == 0 {
		attr.Credential = &syscall.Credential{
			Uid:    uint32(account.UID),
			Gid:    uint32(account.GID),
			Groups: []uint32{uint32(account.GID)},
		}
	}
	return attr
}

// hardenEnterpriseHookWorkerProcess is a no-op on other Unix systems.
func hardenEnterpriseHookWorkerProcess() {}
