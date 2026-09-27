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
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/managed/cloudreg"
	"github.com/defenseclaw/defenseclaw/internal/notify"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// The Secure Client golden pins the gateway posture of a managed_enterprise
// config with no enterprise block: Cisco AI Defense is the only decision
// maker, local detectors are bypassed, requests AI Defense cannot decide fail
// open, inspection needs a registered managed cloud provider, and the Secure
// Client GUI (not the gateway) owns user notifications. Production Secure
// Client deployments rely on every row. See
// testdata/secure_client_golden/README.md.

type secureClientGatewayScenario struct {
	Scenario       string   `json:"scenario"`
	Action         string   `json:"action,omitempty"`
	Severity       string   `json:"severity,omitempty"`
	Findings       []string `json:"findings,omitempty"`
	FailOpenReason string   `json:"fail_open_reason,omitempty"`
	AIDCalls       int      `json:"aid_calls,omitempty"`
	Detail         string   `json:"detail,omitempty"`
}

func secureClientScanScenario(name string, verdict *ScanVerdict, aidCalls int) secureClientGatewayScenario {
	row := secureClientGatewayScenario{Scenario: name, AIDCalls: aidCalls}
	if verdict == nil {
		row.Detail = "<nil verdict>"
		return row
	}
	row.Action = verdict.Action
	row.Severity = verdict.Severity
	row.Findings = verdict.Findings
	return row
}

func secureClientToolScenario(name string, verdict *ToolInspectVerdict, aidCalls int) secureClientGatewayScenario {
	row := secureClientGatewayScenario{Scenario: name, AIDCalls: aidCalls}
	if verdict == nil {
		row.Detail = "<nil verdict>"
		return row
	}
	row.Action = verdict.Action
	row.Severity = verdict.Severity
	row.Findings = verdict.Findings
	row.FailOpenReason = verdict.managedAIDFailOpenReason
	return row
}

func TestSecureClientGoldenGatewayPosture(t *testing.T) {
	var rows []secureClientGatewayScenario
	managedCfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	unmanagedCfg := &config.Config{DeploymentMode: string(config.DeploymentModeUnmanagedBYOD)}

	// User notifications: the Secure Client GUI renders them over the IPC
	// observer lane, so the managed gateway never raises its own OS toast.
	sendNotification := reflect.ValueOf(notify.SendNotification).Pointer()
	for name, cfg := range map[string]*config.Config{"managed": managedCfg, "unmanaged": unmanagedCfg, "nil": nil} {
		sender := osToastSenderFor(cfg)
		kind := "os_toast"
		if reflect.ValueOf(sender).Pointer() != sendNotification {
			kind = "no_op"
			if err := sender(notify.Notification{Title: "golden", Body: "golden"}); err != nil {
				t.Fatalf("managed no-op toast sender returned %v", err)
			}
		}
		rows = append(rows, secureClientGatewayScenario{Scenario: "toast_sender/" + name, Detail: kind})
	}

	// Hook lane selector.
	for name, cfg := range map[string]*config.Config{"managed": managedCfg, "unmanaged": unmanagedCfg} {
		a := &APIServer{scannerCfg: cfg}
		rows = append(rows, secureClientGatewayScenario{
			Scenario: "hook_lane_aid_only/" + name,
			Detail:   fmt.Sprintf("%t", a.managedAIDOnly()),
		})
	}

	// Hook lane: local detectors bypassed, AI Defense authoritative, fail open
	// when AI Defense has no verdict or no inspector is wired.
	shadowRead := &ToolInspectRequest{Tool: "run_shell", Args: json.RawMessage(`{"command":"cat /etc/shadow"}`)}
	secretWrite := &ToolInspectRequest{
		Tool: "write",
		Args: json.RawMessage(`{"path":"config.py","content":"AWS_SECRET = \"AKIAIOSFODNN7EXAMPLE\""}`),
	}
	message := &ToolInspectRequest{Tool: "message", Content: maliciousPrompt}

	aidDown := &stubAIDInspector{verdict: nil}
	a := managedHookServer(aidDown)
	rows = append(rows, secureClientToolScenario("hook_tool_policy/shadow_read/aid_no_verdict", a.inspectToolPolicy(shadowRead), aidDown.calls))
	aidBlock := &stubAIDInspector{verdict: blockVerdict()}
	a = managedHookServer(aidBlock)
	rows = append(rows, secureClientToolScenario("hook_tool_policy/ls/aid_block", a.inspectToolPolicy(&ToolInspectRequest{
		Tool: "run_shell", Args: json.RawMessage(`{"command":"ls"}`),
	}), aidBlock.calls))

	aidDown = &stubAIDInspector{verdict: nil}
	a = managedHookServer(aidDown)
	codeGuard := a.runCodeGuardOnArgs(secretWrite)
	rows = append(rows, secureClientGatewayScenario{
		Scenario: "hook_codeguard/secret_write",
		Detail:   fmt.Sprintf("findings=%d", len(codeGuard)),
	})
	rows = append(rows, secureClientToolScenario("hook_tool_policy/secret_write/aid_no_verdict", a.inspectToolPolicy(secretWrite), aidDown.calls))

	aidDown = &stubAIDInspector{verdict: nil}
	a = managedHookServer(aidDown)
	rows = append(rows, secureClientToolScenario("hook_message/malicious/aid_no_verdict", a.inspectMessageContent(context.Background(), message), aidDown.calls))
	aidBlock = &stubAIDInspector{verdict: blockVerdict()}
	a = managedHookServer(aidBlock)
	rows = append(rows, secureClientToolScenario("hook_message/malicious/aid_block", a.inspectMessageContent(context.Background(), message), aidBlock.calls))

	unwired := &APIServer{scannerCfg: managedCfg}
	rows = append(rows, secureClientToolScenario("hook_managed_aid_only/unwired", unwired.inspectManagedAIDOnly(context.Background(), "run_shell", "cat /etc/shadow"), 0))
	aidDown = &stubAIDInspector{verdict: nil}
	a = managedHookServer(aidDown)
	rows = append(rows, secureClientToolScenario("hook_managed_aid_only/no_content", a.inspectManagedAIDOnly(context.Background(), "run_shell", ""), aidDown.calls))

	// Proxy lane: the same AID-only posture.
	msgs := []ChatMessage{{Role: "user", Content: maliciousPrompt}}
	local := NewGuardrailInspector("local", nil, nil, "")
	rows = append(rows, secureClientScanScenario("proxy/unmanaged_local_baseline", local.Inspect(context.Background(), "prompt", maliciousPrompt, msgs, "gpt", "block"), 0))
	for _, tc := range []struct {
		name    string
		verdict *ScanVerdict
		wire    bool
	}{
		{name: "proxy/managed/unwired", wire: false},
		{name: "proxy/managed/aid_no_verdict", wire: true},
		{name: "proxy/managed/aid_block", verdict: blockVerdict(), wire: true},
	} {
		g := NewGuardrailInspector("both", nil, nil, "")
		g.SetManagedMode(true)
		stub := &stubAIDInspector{verdict: tc.verdict}
		if tc.wire {
			g.SetCiscoInspector(stub)
		}
		rows = append(rows, secureClientScanScenario(tc.name, g.Inspect(context.Background(), "prompt", maliciousPrompt, msgs, "gpt", "block"), stub.calls))
	}
	midStream := NewGuardrailInspector("both", nil, nil, "")
	midStream.SetManagedMode(true)
	midStreamAID := &stubAIDInspector{verdict: blockVerdict()}
	midStream.SetCiscoInspector(midStreamAID)
	rows = append(rows, secureClientScanScenario("proxy/managed/mid_stream_aid_block", midStream.InspectMidStream(
		context.Background(), "completion", maliciousPrompt,
		[]ChatMessage{{Role: "assistant", Content: maliciousPrompt}}, "gpt", "block",
	), midStreamAID.calls))

	// Remote inspection requires a registered managed cloud provider and
	// never falls back to API-key authentication.
	s := managedInspectionSidecar(t)
	inspector := s.pickInspector(context.Background())
	available, detail := s.inspectionAvailability()
	rows = append(rows, secureClientGatewayScenario{
		Scenario: "pick_inspector/managed/no_provider",
		Detail:   fmt.Sprintf("inspector=%T available=%t detail=%s", inspector, available, detail),
	})
	registerFakeCloudProvider(t, newFakeCloudProvider("token"), nil)
	s = managedInspectionSidecar(t)
	inspector = s.pickInspector(context.Background())
	rows = append(rows, secureClientGatewayScenario{
		Scenario: "pick_inspector/managed/registered_provider_no_endpoint",
		Detail:   fmt.Sprintf("inspector=%T", inspector),
	})
	s = managedInspectionSidecar(t)
	s.cfg.CiscoAIDefense.Endpoint = "https://us.api.inspect.aidefense.security.cisco.com"
	inspector = s.pickInspector(context.Background())
	rows = append(rows, secureClientGatewayScenario{
		Scenario: "pick_inspector/managed/registered_provider",
		Detail:   fmt.Sprintf("inspector=%T", inspector),
	})
	cloudreg.Register(nil)

	unmanagedSidecar := &Sidecar{cfg: &config.Config{DataDir: t.TempDir(), DeploymentMode: string(config.DeploymentModeUnmanagedBYOD)}, health: NewSidecarHealth()}
	rows = append(rows, secureClientGatewayScenario{
		Scenario: "pick_inspector/unmanaged/no_api_key",
		Detail:   fmt.Sprintf("inspector=%T", unmanagedSidecar.pickInspector(context.Background())),
	})

	// A multi-connector managed guardrail refuses to boot without a provider.
	conn := &hookBootStubConnector{bootStubConnector: bootStubConnector{stubConnector: stubConnector{name: "codex"}}}
	reg := connector.NewRegistry()
	reg.RegisterBuiltin(conn)
	s = managedInspectionSidecar(t)
	err := s.runManagedEnterpriseMultiHookGuardrail(context.Background(), reg, []connector.Connector{conn}, "gateway-token", "a", "b", "master")
	rows = append(rows, secureClientGatewayScenario{
		Scenario: "multi_hook_guardrail/no_provider",
		Detail: fmt.Sprintf("error=%v state=%s credentials_installed=%t",
			err, s.health.Snapshot().Guardrail.State, conn.credsSet),
	})

	// Runtime configuration changes over the API are denied in managed mode.
	for name, cfg := range map[string]*config.Config{
		"managed_with_token": {
			DeploymentMode: managed.DeploymentModeManagedEnterprise,
			Gateway:        config.GatewayConfig{Token: "gateway-token"},
		},
		"unmanaged_with_token": {
			DeploymentMode: string(config.DeploymentModeUnmanagedBYOD),
			Gateway:        config.GatewayConfig{Token: "gateway-token"},
		},
	} {
		req := httptest.NewRequest(http.MethodPatch, "/v1/guardrail/config", nil)
		req.Header.Set("Authorization", "Bearer gateway-token")
		status, reason := guardrailConfigPatchAuthorization(req, cfg)
		rows = append(rows, secureClientGatewayScenario{
			Scenario: "guardrail_config_patch/" + name,
			Detail:   fmt.Sprintf("status=%d reason=%s", status, reason),
		})
	}

	// Events that carry no identity of their own are never attributed to the
	// managed gateway's service account. Booted last because NewSidecar
	// publishes the process-wide posture that the rows above do not assume.
	withRestoredManagedPosture(t)
	resetConnectorRuleCategories(t)
	withLocalPatternsRestored(t)
	restoreRetainJudgeBodies(t)
	t.Setenv("DEFENSECLAW_RUN_ID", "secure-client-golden")
	bootProfileSidecar(t, profilePostures[1])
	fallback := newLLMEventUser("", "", false)
	rows = append(rows, secureClientGatewayScenario{
		Scenario: "event_user_fallback/managed",
		Detail: fmt.Sprintf("id=%q kind=%q name=%q ai_defense_only=%t inventory_home=%q",
			fallback.ID, fallback.IDKind, fallback.Name, ManagedEnterpriseActive(), daemonHomeForInventoryAttribution()),
	})

	sortSecureClientGatewayRows(rows)
	testenv.CompareSecureClientGoldenJSON(t, "go/gateway_posture.json", rows)
}

func sortSecureClientGatewayRows(rows []secureClientGatewayScenario) {
	for i := 1; i < len(rows); i++ {
		for j := i; j > 0 && rows[j].Scenario < rows[j-1].Scenario; j-- {
			rows[j], rows[j-1] = rows[j-1], rows[j]
		}
	}
}
