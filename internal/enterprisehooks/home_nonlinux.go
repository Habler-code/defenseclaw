//go:build !windows && !linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import "syscall"

// enokey has no equivalent outside Linux; errno 0 never matches an error.
const enokey = syscall.Errno(0)
