//go:build !windows && !linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

// testProcessDumpable has no portable equivalent outside Linux.
func testProcessDumpable() int { return -1 }
