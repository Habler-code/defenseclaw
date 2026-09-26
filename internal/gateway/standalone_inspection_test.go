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
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func standaloneConfig(t *testing.T) *config.Config {
	t.Helper()
	dir := t.TempDir()
	return &config.Config{
		DataDir:        dir,
		ConfigFilePath: filepath.Join(dir, "etc", "config.yaml"),
		DeploymentMode: string(config.DeploymentModeManagedEnterprise),
		Enterprise:     config.EnterpriseConfig{Profile: managed.ProfileStandalone},
		Guardrail:      config.GuardrailConfig{Enabled: true},
	}
}

func TestStandaloneHookLaneKeepsLocalDetectors(t *testing.T) {
	standalone := &APIServer{scannerCfg: standaloneConfig(t)}
	if standalone.managedAIDOnly() {
		t.Fatal("standalone managed deployments must keep the local engine; managedAIDOnly returned true")
	}
	secureClient := &APIServer{scannerCfg: &config.Config{DeploymentMode: string(config.DeploymentModeManagedEnterprise)}}
	if !secureClient.managedAIDOnly() {
		t.Fatal("a Secure Client managed deployment must keep the AID-only posture")
	}
}

func TestStandaloneInspectorWithoutAIDefenseIsLocalOnly(t *testing.T) {
	s := &Sidecar{cfg: standaloneConfig(t), health: NewSidecarHealth()}
	if inspector := s.pickInspector(context.Background()); inspector != nil {
		t.Fatalf("standalone without ai_defense must not build a remote inspector, got %T", inspector)
	}
	if available, detail := s.inspectionAvailability(); !available || detail != "" {
		t.Fatalf("local-only standalone inspection must be available: available=%v detail=%q", available, detail)
	}
}

func TestStandaloneInspectorMissingCredentialDegrades(t *testing.T) {
	cfg := standaloneConfig(t)
	cfg.Enterprise.Inspection.AIDefense = config.EnterpriseAIDefenseConfig{Enabled: true, Credential: "ai-defense-api-key"}
	cfg.CiscoAIDefense.APIKeyEnv = "CISCO_AI_DEFENSE_API_KEY"
	t.Setenv("CISCO_AI_DEFENSE_API_KEY", "must-not-be-used")
	if _, err := newStandaloneCiscoInspectClient(cfg); !errors.Is(err, managed.ErrNoServiceCredential) {
		t.Fatalf("missing protected credential error = %v, want ErrNoServiceCredential (the env key must never be used)", err)
	}
	s := &Sidecar{cfg: cfg, health: NewSidecarHealth()}
	if inspector := s.pickInspector(context.Background()); inspector != nil {
		t.Fatalf("missing credential must not yield an inspector, got %T", inspector)
	}
	if available, _ := s.inspectionAvailability(); available {
		t.Fatal("a configured but missing AI Defense credential must be reported")
	}
}

func TestStandaloneMultiConnectorBootNeedsNoCloudProvider(t *testing.T) {
	resetConnectorRuleCategories(t)
	conn := &hookBootStubConnector{bootStubConnector: bootStubConnector{stubConnector: stubConnector{name: "codex"}}}
	reg := connector.NewRegistry()
	reg.RegisterBuiltin(conn)
	s := &Sidecar{cfg: standaloneConfig(t), health: NewSidecarHealth()}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- s.runManagedEnterpriseMultiHookGuardrail(ctx, reg, []connector.Connector{conn}, "gateway-token", "127.0.0.1:0", "127.0.0.1:0", "master")
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		snapshot := s.health.Snapshot().Guardrail
		if snapshot.State == StateError {
			cancel()
			t.Fatalf("standalone boot failed: %v", snapshot.LastError)
		}
		if detail, ok := snapshot.Details["inspection_available"].(bool); ok {
			if !detail {
				cancel()
				t.Fatalf("standalone local inspection must be reported available: %+v", snapshot.Details)
			}
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("standalone managed guardrail returned %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("standalone managed guardrail did not stop")
	}
	if !conn.credsSet {
		t.Fatal("standalone boot must register the connector for hook evaluation")
	}
}

func TestStandaloneEgressTransportHonorsTheEnterpriseProxy(t *testing.T) {
	cfg := standaloneConfig(t)
	cfg.Enterprise.Network = config.EnterpriseNetworkConfig{HTTPSProxy: "http://proxy.corp:3128", NoProxy: "internal.corp"}
	transport, err := standaloneEgressTransport(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for target, want := range map[string]string{
		"https://us.api.inspect.aidefense.security.cisco.com/api/v1/inspect/chat": "http://proxy.corp:3128",
		"https://aid.internal.corp/api/v1/inspect/chat":                           "",
	} {
		req, err := http.NewRequest(http.MethodPost, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		got, err := transport.Proxy(req)
		if err != nil {
			t.Fatal(err)
		}
		if (got == nil && want != "") || (got != nil && got.String() != want) {
			t.Fatalf("proxy(%s) = %v, want %q", target, got, want)
		}
	}
	cfg.Enterprise.Network.HTTPSProxy = "http://user:secret@proxy.corp:3128"
	if _, err := standaloneEgressTransport(cfg); err == nil {
		t.Fatal("a proxy URL with credentials must be refused")
	}
}
