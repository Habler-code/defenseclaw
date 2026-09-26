// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !darwin && !linux

package hookexec

import (
	"net/http"
	"time"
)

// managedEnterpriseHTTPClient has no kernel source for the owner of the
// connected loopback listener on this platform, so a managed hook refuses
// to send any request byte (Run maps this to the stable fail-closed reason
// enterprise_managed_gateway_peer_unverified). Supported managed platforms
// are Windows (SCM PID), macOS (TCP PCB list) and Linux (sock_diag).
func managedEnterpriseHTTPClient(time.Duration, string, string) (*http.Client, error) {
	return nil, managedGatewayPeerError("gateway listener ownership cannot be verified on this platform")
}
