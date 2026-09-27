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

package gateway

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/peercred"
	"github.com/defenseclaw/defenseclaw/internal/systemd"
)

// inheritedHookListener is replaceable by tests.
var inheritedHookListener = func() (net.Listener, bool, error) { return systemd.Listener("hook") }

// newManagedHookSocketServer builds the standalone hook socket: the same
// hook, notify and inspect handlers as the TCP API, behind kernel-verified
// peer authorization instead of bearer tokens. It returns (nil, nil, nil)
// when the deployment is not standalone.
func (a *APIServer) newManagedHookSocketServer(ctx context.Context, base func(http.Handler) http.Handler) (*http.Server, net.Listener, error) {
	if !managedHookSocketEnabled(a.scannerCfg) {
		return nil, nil, nil
	}
	descriptor, descriptorErr := loadStandaloneRuntimeDescriptor(runtime.GOOS)
	if descriptorErr != nil && !errors.Is(descriptorErr, managed.ErrNoRuntimeDescriptor) {
		// An untrusted descriptor never widens access: fall back to strict
		// per-user enrollment for every connector.
		fmt.Fprintf(os.Stderr, "[sidecar-api] standalone runtime descriptor rejected: %v\n", descriptorErr)
		descriptor = nil
	}
	var machinePolicy []string
	if descriptor != nil {
		machinePolicy = descriptor.MachinePolicyConnectors
	}
	ledger := newManagedHookLedgerLoader(managed.HookGuardianAuthorizationPath(a.configDataDir()))
	authorizer := newManagedHookAuthorizer(a.scannerCfg.Enterprise.Enrollment, machinePolicy, ledger.Load)

	listener, inherited, err := inheritedHookListener()
	if err != nil {
		return nil, nil, err
	}
	if !inherited {
		path := ""
		if descriptor != nil {
			path = descriptor.HookSocket
		}
		if path == "" {
			layout, layoutErr := managed.StandaloneLayoutFor(runtime.GOOS)
			if layoutErr != nil {
				return nil, nil, layoutErr
			}
			path = layout.HookSocketPath
		}
		listener, err = bindManagedHookSocket(path)
		if err != nil {
			return nil, nil, err
		}
	} else if _, ok := listener.Addr().(*net.UnixAddr); !ok {
		_ = listener.Close()
		return nil, nil, fmt.Errorf("api: socket-activated hook listener %s is not a unix socket", listener.Addr())
	}

	handler := base(a.managedHookPeerAuth(authorizer, a.managedHookSocketMux()))
	server := &http.Server{
		Handler:     managedHookPeerIdentityMiddleware(handler),
		BaseContext: func(net.Listener) context.Context { return ctx },
		ConnContext: managedHookConnContext,
	}
	return server, listener, nil
}

// managedHookConnContext stamps each accepted hook-socket connection with
// the peer's kernel credentials. A connection whose credentials cannot be
// read carries none, and the identity middleware refuses its requests.
func managedHookConnContext(ctx context.Context, conn net.Conn) context.Context {
	credentials, err := peercred.FromConn(conn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar-api] hook socket peer credentials unavailable: %v\n", err)
		return ctx
	}
	return withManagedHookPeer(ctx, managedHookPeerFor(credentials))
}

// managedHookPeerFor builds the verified caller identity from kernel
// credentials: account name for attribution, home for "~" resolution.
func managedHookPeerFor(credentials peercred.Credentials) managedHookPeer {
	return managedHookPeer{
		UID:  credentials.UID,
		GID:  credentials.GID,
		PID:  credentials.PID,
		Name: managedHookPeerName(credentials.UID),
		Home: managedHookPeerHome(credentials.UID),
	}
}

// bindManagedHookSocket binds the hook socket when the service manager did
// not pass one (macOS, or Linux without socket activation). The directory
// must already exist, belong to root or this service account and be
// writable by no one else — the lifecycle creates it — so a standard user
// can never have planted a socket there first. A stale socket this account
// owns is replaced; anything else is refused.
func bindManagedHookSocket(path string) (net.Listener, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, fmt.Errorf("api: hook socket path %q is not absolute and clean", path)
	}
	dir := filepath.Dir(path)
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("api: hook socket directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return nil, fmt.Errorf("api: hook socket directory %s is not a real directory", dir)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("api: hook socket directory %s is group/other writable (%04o)", dir, info.Mode().Perm())
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (owner.Uid != 0 && int(owner.Uid) != os.Geteuid()) {
		return nil, fmt.Errorf("api: hook socket directory %s must be owned by root or the service account", dir)
	}
	if existing, err := os.Lstat(path); err == nil {
		if existing.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("api: refusing to replace non-socket %s", path)
		}
		stat, ok := existing.Sys().(*syscall.Stat_t)
		if !ok || int(stat.Uid) != os.Geteuid() {
			return nil, fmt.Errorf("api: refusing to replace hook socket %s owned by another account", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("api: remove stale hook socket: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("api: inspect hook socket: %w", err)
	}
	listener, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("api: listen %s: %w", path, err)
	}
	// Every local user may connect; the server authorizes each caller by
	// its kernel-verified uid.
	if err := os.Chmod(path, 0o666); err != nil {
		_ = listener.Close()
		return nil, fmt.Errorf("api: chmod hook socket: %w", err)
	}
	return listener, nil
}
