//go:build linux || darwin

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
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/peercred"
)

// Hooks for tests; production uses the kernel.
var (
	standalonePeerCredentials = peercred.FromConn
	standaloneTCPListenerUID  = tcpListenerOwnerUID
)

// managedStandaloneHTTPClient is the unix standalone-profile transport. The
// hook trusts the gateway only after the kernel says who is listening:
//
//   - unix socket (preferred): the listener's SO_PEERCRED / LOCAL_PEERCRED
//     uid must be root (a socket held by systemd or launchd) or the gateway
//     service account from the root-owned runtime descriptor;
//   - loopback TCP (only when no socket is configured): the uid that owns
//     the server-side socket of this exact connection must be one of those
//     same accounts.
//
// No request byte is written before that check passes, so a local user who
// wins the listener during a gateway restart receives nothing.
func managedStandaloneHTTPClient(
	timeout time.Duration,
	apiAddr string,
	socketPath string,
	serviceUID int,
) (*http.Client, error) {
	if serviceUID < 0 {
		return nil, standalonePeerError("standalone gateway service uid is not configured")
	}
	if timeout <= 0 {
		timeout = defaultHookRequestTimeout
	}
	var canonicalTCP string
	if socketPath == "" {
		var err error
		canonicalTCP, err = standaloneLoopbackAddress(apiAddr)
		if err != nil {
			return nil, standalonePeerError("%v", err)
		}
	} else if err := validateStandaloneHookSocketPath(socketPath, serviceUID); err != nil {
		return nil, standalonePeerError("%v", err)
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			Proxy:             nil,
			DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
				if socketPath != "" {
					conn, err := dialer.DialContext(ctx, "unix", socketPath)
					if err != nil {
						return nil, err
					}
					credentials, err := standalonePeerCredentials(conn)
					if err != nil {
						_ = conn.Close()
						return nil, standalonePeerError("read hook socket peer credentials: %v", err)
					}
					if !standaloneTrustedGatewayUID(credentials.UID, serviceUID) {
						_ = conn.Close()
						return nil, standalonePeerError(
							"hook socket listener uid %d is neither root nor the gateway service uid %d",
							credentials.UID, serviceUID)
					}
					return conn, nil
				}
				if network != "tcp" && network != "tcp4" {
					return nil, standalonePeerError("unexpected network %q", network)
				}
				if address != canonicalTCP {
					return nil, standalonePeerError("dial target %q does not equal protected gateway %q", address, canonicalTCP)
				}
				conn, err := dialer.DialContext(ctx, "tcp4", canonicalTCP)
				if err != nil {
					return nil, err
				}
				owner, err := standaloneTCPListenerUID(conn)
				if err != nil {
					_ = conn.Close()
					return nil, standalonePeerError("resolve loopback listener owner: %v", err)
				}
				if !standaloneTrustedGatewayUID(owner, serviceUID) {
					_ = conn.Close()
					return nil, standalonePeerError(
						"loopback listener uid %d is neither root nor the gateway service uid %d", owner, serviceUID)
				}
				return conn, nil
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

func standaloneTrustedGatewayUID(uid, serviceUID int) bool {
	return uid == 0 || (serviceUID > 0 && uid == serviceUID)
}

// standaloneLoopbackAddress accepts only an explicit IPv4 loopback address;
// the standalone gateway binds exactly 127.0.0.1.
func standaloneLoopbackAddress(value string) (string, error) {
	host, rawPort, err := net.SplitHostPort(value)
	if err != nil {
		return "", fmt.Errorf("gateway address %q: %w", value, err)
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil || !ip.IsLoopback() {
		return "", fmt.Errorf("gateway address %q is not IPv4 loopback", value)
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil || port <= 0 || port > 65535 {
		return "", fmt.Errorf("gateway port %q is invalid", rawPort)
	}
	return net.JoinHostPort(ip.To4().String(), strconv.Itoa(port)), nil
}

// validateStandaloneHookSocketPath checks the socket before dialing. The
// kernel peer check after connect is the authority; this rejects paths an
// attacker could have arranged and gives a precise diagnostic. The socket's
// directory (after resolving platform symlinks such as macOS /var) must be
// owned by root or the gateway account and writable by no one else.
func validateStandaloneHookSocketPath(path string, serviceUID int) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("hook socket path %q is not absolute and clean", path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("hook socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("hook socket %s is not a socket", path)
	}
	dir, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil {
		return fmt.Errorf("hook socket directory: %w", err)
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("hook socket directory: %w", err)
	}
	if !dirInfo.IsDir() || dirInfo.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("hook socket directory %s must be a directory writable only by its owner", dir)
	}
	stat, ok := dirInfo.Sys().(*syscall.Stat_t)
	if !ok || !standaloneTrustedGatewayUID(int(stat.Uid), serviceUID) {
		return fmt.Errorf("hook socket directory %s is not owned by root or the gateway service account", dir)
	}
	return nil
}

func standalonePeerError(format string, args ...interface{}) error {
	return fmt.Errorf("%w: %s", errManagedGatewayPeerUnverified, fmt.Sprintf(format, args...))
}
