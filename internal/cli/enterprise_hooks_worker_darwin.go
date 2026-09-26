//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"syscall"
)

// enterpriseHookWorkerSysProcAttr starts the worker in its own session and
// — from a root guardian — drops to the exact target uid and gid with only
// the primary group. macOS has no parent-death signal; the parent's
// timeout kills the worker's process group instead.
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

// hardenEnterpriseHookWorkerProcess is a no-op here; macOS already denies
// task ports across users without the debugger entitlement.
func hardenEnterpriseHookWorkerProcess() {}
