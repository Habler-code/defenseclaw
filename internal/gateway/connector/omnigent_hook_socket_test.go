// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// TestOmnigentPolicyBridgeUsesOnlyTheVerifiedHookSocket: a standalone
// OmniGent bridge reaches the gateway through the unix hook socket without
// its scoped credential, never connects to the TCP address (which another
// local user may hold), and denies without sending anything when the socket
// directory could have been written by someone else.
func TestOmnigentPolicyBridgeUsesOnlyTheVerifiedHookSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the standalone hook socket is unix-only")
	}
	python := omnigentTestPython(t)
	templateBytes, err := hookFS.ReadFile("hooks/omnigent-policy.py")
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp("/tmp", "dcog")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	runDir := filepath.Join(root, "run")
	if err := os.Mkdir(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(runDir, "hook.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var requests int
	var authorization, path string
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests++
		authorization, path = r.Header.Get("Authorization"), r.URL.Path
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"block","reason":"verdict from the hook socket"}`))
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	held, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = held.Close() })
	var tcpConnections atomic.Int32
	go func() {
		for {
			conn, err := held.Accept()
			if err != nil {
				return
			}
			tcpConnections.Add(1)
			_ = conn.Close()
		}
	}()

	tokenPath := filepath.Join(root, ".hook-omnigent.token")
	if err := os.WriteFile(tokenPath, []byte(strings.Repeat("d", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	modulePath := filepath.Join(root, "defenseclaw_omnigent_policy.py")
	rendered := renderOmnigentPolicyWithTransport(string(templateBytes), held.Addr().String(), tokenPath, "open", socketPath, os.Getuid())
	if err := os.WriteFile(modulePath, []byte(rendered), 0o600); err != nil {
		t.Fatal(err)
	}
	evaluate := func() map[string]string {
		t.Helper()
		script := `
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("defenseclaw_omnigent_policy", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
print(json.dumps(module.defenseclaw_policy({"type": "tool_call", "target": "shell", "data": {"name": "shell", "arguments": {"command": "echo marker"}}})))
`
		output, err := exec.Command(python, "-c", script, modulePath).CombinedOutput()
		if err != nil {
			t.Fatalf("execute policy: %v\n%s", err, output)
		}
		var verdict map[string]string
		if err := json.Unmarshal(output, &verdict); err != nil {
			t.Fatalf("decode verdict %q: %v", output, err)
		}
		return verdict
	}

	if verdict := evaluate(); verdict["result"] != "DENY" || verdict["reason"] != "verdict from the hook socket" {
		t.Fatalf("verdict over the hook socket = %v", verdict)
	}
	mu.Lock()
	if requests != 1 || path != "/api/v1/omnigent/hook" || authorization != "" {
		mu.Unlock()
		t.Fatalf("hook socket request: count=%d path=%q authorization=%q, want one bearer-free omnigent hook request", requests, path, authorization)
	}
	mu.Unlock()

	// Even with the operator's fail-open transport mode, an unverified socket
	// denies instead of allowing.
	if err := os.Chmod(runDir, 0o777); err != nil {
		t.Fatal(err)
	}
	if verdict := evaluate(); verdict["result"] != "DENY" || !strings.Contains(verdict["reason"], "hook socket") {
		t.Fatalf("verdict with an untrusted socket directory = %v, want a hook socket denial", verdict)
	}
	mu.Lock()
	count := requests
	mu.Unlock()
	if count != 1 {
		t.Fatalf("the bridge sent a request through an unverified socket (%d requests)", count)
	}
	if n := tcpConnections.Load(); n != 0 {
		t.Fatalf("the standalone bridge connected to the TCP API address %d times", n)
	}
}

// TestOmnigentSetupRendersTheHookSocketOnlyForManagedStandalone pins the
// Setup gate: a managed install that names a socket renders it, and every
// other install renders the empty (TCP) transport.
func TestOmnigentSetupRendersTheHookSocketOnlyForManagedStandalone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the standalone hook socket is unix-only")
	}
	templateBytes, err := hookFS.ReadFile("hooks/omnigent-policy.py")
	if err != nil {
		t.Fatal(err)
	}
	encode := func(value string) string { return base64.StdEncoding.EncodeToString([]byte(value)) }
	for _, test := range []struct {
		name       string
		opts       SetupOpts
		wantSocket string
		wantUID    string
	}{
		{name: "per-user", opts: SetupOpts{ManagedHookSocket: "/run/defenseclaw-hook/hook.sock", ManagedServiceUID: 995}},
		{name: "managed without socket", opts: SetupOpts{ManagedEnterprise: true}},
		{name: "managed standalone", opts: SetupOpts{ManagedEnterprise: true, ManagedHookSocket: "/run/defenseclaw-hook/hook.sock", ManagedServiceUID: 995},
			wantSocket: "/run/defenseclaw-hook/hook.sock", wantUID: strconv.Itoa(995)},
	} {
		socket, uid := managedPluginHookSocket(test.opts)
		rendered := renderOmnigentPolicyWithTransport(string(templateBytes), "127.0.0.1:18970", "/t", "closed", socket, uid)
		if !strings.Contains(rendered, `_HOOK_SOCKET = _decoded("`+encode(test.wantSocket)+`")`) ||
			!strings.Contains(rendered, `int(_decoded("`+encode(test.wantUID)+`") or "0")`) {
			t.Fatalf("%s: rendered transport does not carry socket %q uid %q", test.name, test.wantSocket, test.wantUID)
		}
		if strings.Contains(rendered, "{{HOOK_SOCKET_B64}}") || strings.Contains(rendered, "{{SERVICE_UID_B64}}") {
			t.Fatalf("%s: a transport placeholder was left unrendered", test.name)
		}
	}
}
