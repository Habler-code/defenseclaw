//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import "golang.org/x/sys/unix"

// testProcessDumpable reports PR_GET_DUMPABLE for the calling process.
func testProcessDumpable() int {
	value, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		return -1
	}
	return value
}
