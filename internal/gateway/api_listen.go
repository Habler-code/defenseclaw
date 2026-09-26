// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/systemd"
)

// inheritedAPIListener is replaceable by tests.
var inheritedAPIListener = func() (net.Listener, bool, error) { return systemd.Listener("api") }

// acquireAPIListener returns the API listener: the socket-activated "api"
// descriptor when systemd passed one, otherwise a bound listener. An
// inherited socket must be exactly the configured api_bind:api_port — a
// mismatch fails closed rather than silently serving the API somewhere the
// managed config did not name.
func (a *APIServer) acquireAPIListener(ctx context.Context) (net.Listener, error) {
	listener, inherited, err := inheritedAPIListener()
	if err != nil {
		return nil, err
	}
	if inherited {
		if err := inheritedAddrMatches(listener.Addr(), a.addr); err != nil {
			_ = listener.Close()
			return nil, err
		}
		return listener, nil
	}
	return listenWithRetry(ctx, a.addr, 30*time.Second)
}

func inheritedAddrMatches(actual net.Addr, configured string) error {
	host, rawPort, err := net.SplitHostPort(configured)
	if err != nil {
		return fmt.Errorf("api: configured address %q: %w", configured, err)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		return fmt.Errorf("api: configured port %q: %w", rawPort, err)
	}
	tcp, ok := actual.(*net.TCPAddr)
	if !ok {
		return fmt.Errorf("api: socket-activated listener %s is not TCP", actual)
	}
	want := net.ParseIP(host)
	if host == "localhost" {
		want = net.IPv4(127, 0, 0, 1)
	}
	if want == nil || !tcp.IP.Equal(want) || tcp.Port != port {
		return fmt.Errorf("api: socket-activated listener %s does not match configured %s", actual, configured)
	}
	return nil
}
