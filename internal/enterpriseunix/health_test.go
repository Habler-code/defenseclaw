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
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/peercred"
)

// MAC-F24 on Linux: the gateway unit runs and serves its hook socket, but
// another account holds 127.0.0.1:18970 and the gateway reports its API
// listener as retrying. Status reported the gateway ready (a 200 was taken
// as readiness) and did not name the holder.
func TestLinuxGatewayWithoutItsAPIPortIsNotReady(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	plantLinuxListener(t, h, "31337", "4242")
	h.env.HealthGet = func(context.Context) (int, []byte, error) { return 200, []byte(retryingAPIHealth), nil }
	want := "the gateway API port 127.0.0.1:18970 is held by pid 31337 (uid 4242"

	status := h.run(Options{Action: ActionStatus})
	if status.Readiness.Gateway || status.CoverageComplete {
		t.Fatalf("status reports the gateway ready without its API port: %+v", status.Readiness)
	}
	if got := messagesOf(status.Warnings, codeVerify); !strings.Contains(got, want) || !strings.Contains(got, "serves hooks on its socket and keeps retrying the port") {
		t.Fatalf("status does not name the port holder: %s", got)
	}
	if got := messagesOf(h.run(Options{Action: ActionVerify}).Errors, codeVerify); !strings.Contains(got, want) {
		t.Fatalf("verify does not name the port holder: %s", got)
	}
}

// When the holder cannot be seen (it exited, or lsof shows only the
// caller's own processes), the gateway's own report still says why it is
// not ready.
func TestGatewayAPIListenerDownWithoutAVisibleHolder(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			h.env.HealthGet = func(context.Context) (int, []byte, error) { return 200, []byte(retryingAPIHealth), nil }
			status := h.run(Options{Action: ActionStatus})
			if status.Readiness.Gateway {
				t.Fatal("status reports the gateway ready without its API port")
			}
			got := messagesOf(status.Warnings, codeVerify)
			if !strings.Contains(got, "its API listener 127.0.0.1:18970 is not up (error: listen tcp 127.0.0.1:18970: bind: address already in use); the gateway keeps retrying the port") {
				t.Fatalf("status does not explain the API listener: %s", got)
			}
		})
	}
}

// Readiness needs the gateway on the hook socket on Linux too: its health
// document is read there, so the listener must be PID 1 (the socket unit),
// root, or the service account.
func TestLinuxHookSocketListenerIsChecked(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	h.env.HookSocketPeer = func(context.Context) (peercred.Credentials, error) {
		return peercred.Credentials{UID: 1001, GID: 1001, PID: 4321}, nil
	}
	if status := h.run(Options{Action: ActionStatus}); status.Readiness.Gateway {
		t.Fatal("status reports the gateway ready with another account on the hook socket")
	}
	if got := messagesOf(h.run(Options{Action: ActionVerify}).Errors, codeVerify); !strings.Contains(got, "is served by uid 1001") {
		t.Fatalf("verify does not name the hook socket listener: %s", got)
	}

	// systemd holds the socket-activated listener.
	h.env.HookSocketPeer = func(context.Context) (peercred.Credentials, error) {
		return peercred.Credentials{UID: 0, GID: 0, PID: 1}, nil
	}
	status := h.run(Options{Action: ActionStatus})
	if !status.Readiness.Gateway || status.Inspection.Local != "active" {
		t.Fatalf("a socket-activated hook socket must count as the gateway's: %+v %+v %+v", status.Readiness, status.Inspection, status.Warnings)
	}
}

// A gateway from an earlier release refuses /health on its hook socket (the
// path has no connector scope there). Between a package upgrade and the
// restart, and after a rollback, readiness falls back to the TCP API; on
// macOS a process other than the gateway on that port still fails it.
func TestEarlierGatewayIsProbedOnTheAPIPort(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			h.env.HealthGet = func(context.Context) (int, []byte, error) {
				return http.StatusForbidden, []byte(`{"error":"forbidden","reason":"connector_unknown"}`), nil
			}
			h.env.APIHealthGet = func(context.Context) (int, []byte, error) {
				return 200, []byte(`{"inspection":{"local":"active","ai_defense":"disabled"}}`), nil
			}
			if status := h.run(Options{Action: ActionStatus}); !status.Readiness.Gateway || status.Inspection.Local != "active" {
				t.Fatalf("an earlier gateway answering on its API port must be ready: %+v %+v", status.Readiness, status.Warnings)
			}
			if got := messagesOf(h.run(Options{Action: ActionVerify}).Errors, codeVerify); strings.Contains(got, "gateway") {
				t.Fatalf("verify refused an earlier gateway answering on its API port: %s", got)
			}
			if goos != "darwin" {
				return
			}
			h.env.Runner = lsofRunner{Runner: h.runner, output: "p94782\nu4243\nf5\n"}
			status := h.run(Options{Action: ActionStatus})
			if status.Readiness.Gateway || !strings.Contains(messagesOf(status.Warnings, codeVerify), "is held by pid 94782 (uid 4243") {
				t.Fatalf("an answer from another holder of the API port was trusted: %+v %+v", status.Readiness, status.Warnings)
			}
		})
	}
}

// A failed activation names the port holder once: the readiness error
// already carries it.
func TestFailedActivationNamesThePortHolderOnce(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	h.env.Runner = lsofRunner{Runner: h.runner, output: "p94782\nu4243\nf5\n"}
	h.env.HealthGet = func(context.Context) (int, []byte, error) { return 200, []byte(retryingAPIHealth), nil }
	r := h.run(Options{Action: ActionRepair})
	requireError(t, r, codeActivate)
	if got := messagesOf(r.Errors, codeActivate); strings.Count(got, "is held by pid 94782") != 1 || !strings.Contains(got, "did not become ready") {
		t.Fatalf("repair must name the port holder once: %s", got)
	}
}

// The production probe speaks HTTP over the hook socket, with the API
// address as Host, and returns the gateway's document.
func TestHealthIsReadOverTheHookSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "dchh")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "hook.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	hosts := make(chan string, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hosts <- r.Host
		if r.URL.Path != "/health" || r.Method != http.MethodGet {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"api": map[string]any{"state": "running"}})
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	layout, err := managed.StandaloneLayoutFor("linux")
	if err != nil {
		t.Fatal(err)
	}
	layout.HookSocketPath = path
	env := &Env{GOOS: "linux", Layout: layout}
	env.fillDefaults()
	code, body, err := env.HealthGet(context.Background())
	if err != nil || code != http.StatusOK || !strings.Contains(string(body), `"running"`) {
		t.Fatalf("health over the hook socket: %d %s %v", code, body, err)
	}
	if host := <-hosts; host != layout.APIAddr {
		t.Fatalf("Host %q, want %q", host, layout.APIAddr)
	}
	env.Layout.HookSocketPath = filepath.Join(dir, "missing.sock")
	env.HealthGet = nil
	env.fillDefaults()
	if _, _, err := env.HealthGet(context.Background()); err == nil {
		t.Fatalf("a missing hook socket answered: %v", err)
	}
}
