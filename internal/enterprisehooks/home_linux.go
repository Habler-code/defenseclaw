//go:build linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import "syscall"

// enokey is fscrypt's "key not available" error for a locked home.
const enokey = syscall.ENOKEY
