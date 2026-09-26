//go:build !linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"errors"
	"net"
)

// tcpListenerOwnerUID: only Linux exposes the owner of another process's
// TCP socket to an unprivileged caller without parsing private kernel
// structures (macOS pcblist). Standalone macOS hooks use the unix socket;
// the TCP fallback therefore fails closed here.
func tcpListenerOwnerUID(net.Conn) (int, error) {
	return 0, errors.New("loopback listener ownership cannot be verified on this platform; use the hook socket")
}
