// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/peercred"
)

// On macOS the gateway binds 127.0.0.1:18970 itself. A local process that
// bound the port first can answer /health while the real gateway retries its
// bind and launchd reports it running, and it never serves the hook socket.
// Readiness and verify require the gateway account on the hook socket.
func TestDarwinReadinessNeedsTheGatewayOnTheHookSocket(t *testing.T) {
	for name, peer := range map[string]func(h *testHost) (peercred.Credentials, error){
		"hook socket not served": func(*testHost) (peercred.Credentials, error) {
			return peercred.Credentials{}, errors.New("connection refused")
		},
		"hook socket served by another account": func(*testHost) (peercred.Credentials, error) {
			return peercred.Credentials{UID: 501, GID: 20}, nil
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newTestHost(t, "darwin")
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			// Another process answers /health on the gateway port.
			h.env.HealthGet = func(context.Context) (int, []byte, error) { return 200, []byte(`{}`), nil }
			h.env.HookSocketPeer = func(context.Context) (peercred.Credentials, error) { return peer(h) }

			verify := h.run(Options{Action: ActionVerify})
			joined := ""
			for _, e := range verify.Errors {
				joined += e.Message + "\n"
			}
			if !strings.Contains(joined, "hook socket") {
				t.Fatalf("verify accepted a /health answer without the gateway on the hook socket: %+v", verify.Errors)
			}
			if status := h.run(Options{Action: ActionStatus}); status.Readiness.Gateway {
				t.Fatal("status reports the gateway ready without it on the hook socket")
			}

			r := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("2.0.0")})
			requireError(t, r, codeActivate)
			if record, _ := h.env.loadDeployment(); record.ProductVersion != "1.0.0" {
				t.Fatalf("the upgrade committed without a serving gateway: %+v", record)
			}
		})
	}
}

// The production probe reports the listening process's kernel credentials.
func TestHookSocketPeerReportsTheListener(t *testing.T) {
	dir, err := os.MkdirTemp("", "dchs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "hook.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	peer, err := hookSocketPeer(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if peer.UID != os.Geteuid() {
		t.Fatalf("peer uid %d, want %d", peer.UID, os.Geteuid())
	}
	if peer.PID != 0 && peer.PID != os.Getpid() {
		t.Fatalf("peer pid %d, want %d", peer.PID, os.Getpid())
	}
	if _, err := hookSocketPeer(context.Background(), filepath.Join(dir, "missing.sock")); err == nil {
		t.Fatal("a missing hook socket was reported as served")
	}
}
