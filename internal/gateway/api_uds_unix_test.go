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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	osuser "os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func shortGatewaySocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "dcg")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func TestBindManagedHookSocket(t *testing.T) {
	dir := shortGatewaySocketDir(t)
	path := filepath.Join(dir, "hook.sock")
	listener, err := bindManagedHookSocket(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm() != 0o666 {
		t.Fatalf("socket not created as a world-connectable socket: %v %v", info, err)
	}
	_ = listener.Close()

	// A stale socket this account owns is replaced.
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if unixListener, ok := stale.(*net.UnixListener); ok {
		unixListener.SetUnlinkOnClose(false)
	}
	_ = stale.Close()
	listener, err = bindManagedHookSocket(path)
	if err != nil {
		t.Fatalf("stale own socket not replaced: %v", err)
	}
	_ = listener.Close()

	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bindManagedHookSocket(regular); err == nil {
		t.Fatal("a regular file must never be replaced")
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := bindManagedHookSocket(filepath.Join(dir, "other.sock")); err == nil {
		t.Fatal("a world-writable socket directory must be refused")
	}
	if _, err := bindManagedHookSocket("relative.sock"); err == nil {
		t.Fatal("relative socket path must be refused")
	}
}

// TestManagedHookSocketServesOnlyAuthorizedHookRoutes runs the real hook
// socket server: kernel credentials identify the caller, the ledger and the
// descriptor decide, and management routes are not reachable at all.
func TestManagedHookSocketServesOnlyAuthorizedHookRoutes(t *testing.T) {
	dir := shortGatewaySocketDir(t)
	socket := filepath.Join(dir, "hook.sock")
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, "")
	ledgerDir := managed.HookGuardianAuthorizationDir(dataDir)
	if err := os.MkdirAll(ledgerDir, 0o700); err != nil {
		t.Fatal(err)
	}
	current, err := osuser.Current()
	if err != nil {
		t.Fatal(err)
	}
	ledger := fmt.Sprintf(`{"version":1,"ok":true,"protected_targets":[{"user":%q,"connector":"claudecode","ok":true}]}`, current.Username)
	if err := os.WriteFile(managed.HookGuardianAuthorizationPath(dataDir), []byte(ledger), 0o600); err != nil {
		t.Fatal(err)
	}

	restoreValidate := validateManagedGuardianAuthorization
	restoreDescriptor := loadStandaloneRuntimeDescriptor
	restoreInherited := inheritedHookListener
	t.Cleanup(func() {
		validateManagedGuardianAuthorization = restoreValidate
		loadStandaloneRuntimeDescriptor = restoreDescriptor
		inheritedHookListener = restoreInherited
	})
	validateManagedGuardianAuthorization = func(string, string) error { return nil }
	loadStandaloneRuntimeDescriptor = func(string) (*managed.RuntimeDescriptor, error) {
		return &managed.RuntimeDescriptor{
			SchemaVersion:           managed.RuntimeDescriptorSchemaVersion,
			Profile:                 managed.ProfileStandalone,
			ServiceUser:             current.Username,
			ServiceUID:              os.Getuid(),
			APIAddr:                 managed.StandaloneAPIAddr,
			HookSocket:              socket,
			MachinePolicyConnectors: []string{"codex"},
		}, nil
	}
	inheritedHookListener = func() (net.Listener, bool, error) { return nil, false, nil }

	store, logger := testStoreAndV8Logger(t)
	cfg := &config.Config{DeploymentMode: "managed_enterprise", DataDir: dataDir}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	cfg.Guardrail.Mode = "observe"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, store, logger, cfg)
	api.SetConnectorRegistry(connector.NewDefaultRegistry())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server, listener, err := api.newManagedHookSocketServer(ctx, func(h http.Handler) http.Handler { return h })
	if err != nil || server == nil {
		t.Fatalf("hook socket server: %v %v", server, err)
	}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		}},
	}
	post := func(path string, headers map[string]string, body interface{}) (int, string) {
		t.Helper()
		payload, _ := json.Marshal(body)
		request, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:18970"+path, bytes.NewReader(payload))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-DefenseClaw-Client", "claude-code-hook/1.0")
		for key, value := range headers {
			request.Header.Set(key, value)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(data)
	}
	event := map[string]interface{}{
		"hook_event_name": "PreToolUse", "session_id": "s1", "tool_use_id": "t1",
		"tool_name": "Bash", "tool_input": map[string]interface{}{"command": "echo hello"},
	}

	if status, body := post("/api/v1/claude-code/hook", nil, event); status == http.StatusForbidden || status == http.StatusUnauthorized {
		t.Fatalf("enrolled per-user connector refused: %d %s", status, body)
	}
	if status, body := post("/api/v1/cursor/hook", nil, event); status != http.StatusForbidden || !strings.Contains(body, managedHookReasonUIDUnregistered) {
		t.Fatalf("unenrolled per-user connector: %d %s", status, body)
	}
	if status, body := post("/api/v1/inspect/tool", map[string]string{"X-DefenseClaw-Connector": "cursor"},
		map[string]interface{}{"tool": "Bash", "args": map[string]interface{}{"command": "id"}}); status != http.StatusForbidden {
		t.Fatalf("inspect for an unenrolled connector: %d %s", status, body)
	}
	if status, body := post("/api/v1/inspect/tool", map[string]string{"X-DefenseClaw-Connector": "claudecode"},
		map[string]interface{}{"tool": "Bash", "args": map[string]interface{}{"command": "id"}}); status == http.StatusForbidden || status == http.StatusUnauthorized {
		t.Fatalf("inspect for the enrolled connector refused: %d %s", status, body)
	}
	for _, path := range []string{"/status", "/config/patch", "/enforce/allow", "/v1/guardrail/config", "/api/v1/admin/shutdown"} {
		if status, _ := post(path, map[string]string{"Authorization": "Bearer anything"}, map[string]string{}); status != http.StatusNotFound && status != http.StatusForbidden {
			t.Fatalf("management route %s reachable on the hook socket: %d", path, status)
		}
	}
}
