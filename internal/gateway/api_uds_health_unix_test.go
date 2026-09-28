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
	"encoding/json"
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

// MAC-F24: the Linux and macOS lifecycle reads gateway readiness from the
// hook socket, because another local account can hold 127.0.0.1:18970 and
// answer /health there. The socket answers GET /health for any local
// caller, as the TCP API does, and reports the API listener's state; every
// other route still needs peer authorization.
func TestManagedHookSocketServesHealth(t *testing.T) {
	dir := shortGatewaySocketDir(t)
	socket := filepath.Join(dir, "hook.sock")
	dataDir := filepath.Join(dir, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, "")
	current, err := osuser.Current()
	if err != nil {
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
			SchemaVersion: managed.RuntimeDescriptorSchemaVersion,
			Profile:       managed.ProfileStandalone,
			ServiceUser:   current.Username,
			ServiceUID:    os.Getuid(),
			APIAddr:       managed.StandaloneAPIAddr,
			HookSocket:    socket,
		}, nil
	}
	inheritedHookListener = func() (net.Listener, bool, error) { return nil, false, nil }

	store, logger := testStoreAndV8Logger(t)
	cfg := &config.Config{DeploymentMode: "managed_enterprise", DataDir: dataDir}
	cfg.Enterprise.Profile = managed.ProfileStandalone
	cfg.Guardrail.Mode = "observe"
	health := NewSidecarHealth()
	health.SetAPI(StateError, "listen tcp 127.0.0.1:18970: bind: address already in use",
		map[string]interface{}{"addr": "127.0.0.1:18970", "tcp_bind_retrying": true})
	api := NewAPIServer("127.0.0.1:0", health, nil, store, logger, cfg)
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
	call := func(method, path string) (int, []byte) {
		t.Helper()
		request, _ := http.NewRequest(method, "http://127.0.0.1:18970"+path, strings.NewReader("{}"))
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		return response.StatusCode, data
	}

	// The caller has no ledger row and sends no credential.
	status, body := call(http.MethodGet, "/health")
	if status != http.StatusOK {
		t.Fatalf("GET /health on the hook socket: %d %s", status, body)
	}
	var document struct {
		API struct {
			State   string                 `json:"state"`
			Details map[string]interface{} `json:"details"`
		} `json:"api"`
		Provenance map[string]interface{} `json:"provenance"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatalf("health document: %v\n%s", err, body)
	}
	if document.API.State != string(StateError) || document.API.Details["tcp_bind_retrying"] != true || document.Provenance == nil {
		t.Fatalf("the hook socket health must carry the API listener state: %s", body)
	}
	if status, body := call(http.MethodPost, "/health"); status == http.StatusOK {
		t.Fatalf("POST /health must not bypass peer authorization: %d %s", status, body)
	}
	if status, body := call(http.MethodGet, "/status"); status != http.StatusForbidden && status != http.StatusNotFound {
		t.Fatalf("a management route is reachable on the hook socket: %d %s", status, body)
	}
}
