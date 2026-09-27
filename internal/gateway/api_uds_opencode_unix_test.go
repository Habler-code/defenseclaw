//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
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

// The managed OpenCode plugin reaches the gateway through the hook binary
// over the hook socket for users DefenseClaw never enrolled per user: once
// the descriptor records OpenCode as machine policy the socket admits every
// local user for it and answers with the hook_output the plugin applies.
// Without that record an unenrolled user stays refused.
func TestManagedHookSocketAdmitsTheManagedOpenCodePlugin(t *testing.T) {
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
	inheritedHookListener = func() (net.Listener, bool, error) { return nil, false, nil }
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, "")

	post := func(t *testing.T, machinePolicy []string) (int, string) {
		t.Helper()
		dir := shortGatewaySocketDir(t)
		socket := filepath.Join(dir, "hook.sock")
		dataDir := filepath.Join(dir, "data")
		ledgerDir := managed.HookGuardianAuthorizationDir(dataDir)
		if err := os.MkdirAll(ledgerDir, 0o700); err != nil {
			t.Fatal(err)
		}
		// A healthy ledger that enrolls nobody for OpenCode.
		if err := os.WriteFile(managed.HookGuardianAuthorizationPath(dataDir), []byte(`{"version":1,"ok":true,"protected_targets":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		loadStandaloneRuntimeDescriptor = func(string) (*managed.RuntimeDescriptor, error) {
			return &managed.RuntimeDescriptor{
				SchemaVersion:           managed.RuntimeDescriptorSchemaVersion,
				Profile:                 managed.ProfileStandalone,
				ServiceUser:             current.Username,
				ServiceUID:              os.Getuid(),
				APIAddr:                 managed.StandaloneAPIAddr,
				HookSocket:              socket,
				MachinePolicyConnectors: machinePolicy,
			}, nil
		}
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
		// The payload the managed plugin hands the hook binary, which
		// forwards it unchanged with the plugin's client name.
		payload, _ := json.Marshal(map[string]interface{}{
			"hook_event_name": "tool.execute.before", "tool_name": "bash",
			"tool_input": map[string]interface{}{"command": "echo hello"},
			"session_id": "s1", "tool_call_id": "c1", "cwd": dir,
			"load_heartbeat": true, "arguments_authoritative": true, "mcp_identity_status": "not_mcp",
		})
		request, _ := http.NewRequest(http.MethodPost, "http://127.0.0.1:18970/api/v1/opencode/hook", bytes.NewReader(payload))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("X-DefenseClaw-Client", "opencode-plugin/1.0")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		return response.StatusCode, string(body)
	}

	status, body := post(t, []string{"opencode"})
	if status != http.StatusOK {
		t.Fatalf("machine-policy OpenCode refused for an unenrolled user: %d %s", status, body)
	}
	// The plugin reads mode and, on a block, hook_output.decision.
	var answer struct {
		Action     string                 `json:"action"`
		Mode       string                 `json:"mode"`
		HookOutput map[string]interface{} `json:"hook_output"`
	}
	if err := json.Unmarshal([]byte(body), &answer); err != nil || answer.Mode != "observe" || answer.Action != "allow" {
		t.Fatalf("unexpected answer for an allowed call: %v %s", err, body)
	}
	if decision, _ := answer.HookOutput["decision"].(string); decision == "deny" || decision == "block" {
		t.Fatalf("an allowed call must not carry a block decision: %s", body)
	}
	if status, body := post(t, nil); status != http.StatusForbidden || !strings.Contains(body, managedHookReasonUIDUnregistered) {
		t.Fatalf("per-user OpenCode for an unenrolled user: %d %s", status, body)
	}
}
