// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin || linux

package hookexec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// errManagedListenerPending reports that the kernel does not (yet) show an
// established server-side socket for the exact connected tuple. It is the
// only lookup result that is retried; every other failure is final.
var errManagedListenerPending = errors.New("server side of the connected socket is not established yet")

const (
	managedListenerLookupAttempts = 20
	managedListenerLookupBackoff  = 5 * time.Millisecond
)

var (
	// managedEnterpriseVerifyListener inspects the kernel's record of the
	// server side of conn and returns nil only when it belongs to the managed
	// gateway identity for this platform. Tests replace it.
	managedEnterpriseVerifyListener = verifyManagedGatewayListener
	managedEnterpriseDialContext    = (&net.Dialer{Timeout: 2 * time.Second}).DialContext
)

// managedEnterpriseHTTPClient authenticates the process behind the exact
// connected loopback TCP socket before net/http receives the connection and
// can write the bearer token or any request byte. The managed gateway runs
// as a privileged service (macOS: the root LaunchDaemon; Linux: root or the
// packaged service account), so the owner of the server-side socket for this
// connection's 4-tuple must be that identity. The lookup runs after connect,
// on the socket the kernel actually paired with this client, so a process
// that bound the port while the gateway was restarting is refused before it
// receives any data. The service name argument is Windows-only (SCM).
func managedEnterpriseHTTPClient(
	timeout time.Duration,
	apiAddr string,
	_ string,
) (*http.Client, error) {
	canonicalAddr, err := normalizeManagedGatewayAddress(apiAddr)
	if err != nil {
		return nil, managedGatewayPeerError("%v", err)
	}
	if timeout <= 0 {
		timeout = defaultHookRequestTimeout
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// One verified dial per request: a pooled connection would skip
			// the listener check for every request after the first.
			DisableKeepAlives: true,
			Proxy:             nil,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" && network != "tcp4" {
					return nil, managedGatewayPeerError("unexpected network %q", network)
				}
				if address != canonicalAddr {
					return nil, managedGatewayPeerError(
						"dial target %q does not equal protected gateway %q",
						address,
						canonicalAddr,
					)
				}
				conn, err := managedEnterpriseDialContext(ctx, "tcp4", canonicalAddr)
				if err != nil {
					return nil, err
				}
				if err := verifyManagedGatewayConn(ctx, conn); err != nil {
					_ = conn.Close()
					return nil, managedGatewayPeerError("%v", err)
				}
				return conn, nil
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// verifyManagedGatewayConn retries only while the kernel has not published
// an established server-side socket for the tuple (the final handshake ACK
// can be processed just after connect returns). A socket owned by any other
// identity fails immediately.
func verifyManagedGatewayConn(ctx context.Context, conn net.Conn) error {
	var err error
	for attempt := 1; ; attempt++ {
		err = managedEnterpriseVerifyListener(conn)
		if err == nil {
			return nil
		}
		if !errors.Is(err, errManagedListenerPending) || attempt >= managedListenerLookupAttempts {
			return err
		}
		timer := time.NewTimer(managedListenerLookupBackoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fmt.Errorf("%v: %w", err, ctx.Err())
		case <-timer.C:
		}
	}
}

// managedConnEndpoints returns the IPv4 client (local) and server (remote)
// endpoints of an established TCP connection.
func managedConnEndpoints(conn net.Conn) (client, server managedIPv4Endpoint, err error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return client, server, fmt.Errorf("connected socket has type %T, want *net.TCPConn", conn)
	}
	client, err = managedIPv4EndpointFromAddr(tcpConn.LocalAddr())
	if err != nil {
		return client, server, fmt.Errorf("parse client endpoint: %w", err)
	}
	server, err = managedIPv4EndpointFromAddr(tcpConn.RemoteAddr())
	if err != nil {
		return client, server, fmt.Errorf("parse server endpoint: %w", err)
	}
	return client, server, nil
}

type managedIPv4Endpoint struct {
	addr [4]byte
	port uint16
}

func managedIPv4EndpointFromAddr(addr net.Addr) (managedIPv4Endpoint, error) {
	tcpAddr, ok := addr.(*net.TCPAddr)
	if !ok {
		return managedIPv4Endpoint{}, fmt.Errorf("address has type %T, want *net.TCPAddr", addr)
	}
	ip := tcpAddr.IP.To4()
	if ip == nil || tcpAddr.Port < 1 || tcpAddr.Port > 65535 {
		return managedIPv4Endpoint{}, fmt.Errorf("address %q is not a valid IPv4 TCP endpoint", addr.String())
	}
	var result managedIPv4Endpoint
	copy(result.addr[:], ip)
	result.port = uint16(tcpAddr.Port)
	return result, nil
}

func (e managedIPv4Endpoint) String() string {
	return net.JoinHostPort(net.IP(e.addr[:]).String(), fmt.Sprint(e.port))
}
