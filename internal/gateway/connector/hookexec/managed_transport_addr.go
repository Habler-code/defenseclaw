// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// managedGatewayPeerError wraps errManagedGatewayPeerUnverified so every
// platform's managed transport surfaces the same stable, fail-closed reason
// (managedGatewayPeerUnverifiedReason) through Run and RunCodexNotify.
func managedGatewayPeerError(format string, args ...interface{}) error {
	return fmt.Errorf("%w: %s", errManagedGatewayPeerUnverified, fmt.Sprintf(format, args...))
}

// normalizeManagedGatewayAddress accepts only the exact canonical IPv4
// loopback form the managed installers publish. Every managed transport
// verifies the listener behind this one address; aliases (localhost, other
// 127/8 addresses, IPv6, zero-padded ports) are rejected rather than
// resolved so the dial target and the verified socket cannot diverge.
func normalizeManagedGatewayAddress(value string) (string, error) {
	if value == "" || value != strings.TrimSpace(value) {
		return "", errors.New("managed gateway address is not canonical")
	}
	host, rawPort, err := net.SplitHostPort(value)
	if err != nil {
		return "", fmt.Errorf("managed gateway address is not host:port: %w", err)
	}
	if host != "127.0.0.1" {
		return "", errors.New("managed gateway address must use exact canonical 127.0.0.1")
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != rawPort {
		return "", errors.New("managed gateway port is not canonical")
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}
