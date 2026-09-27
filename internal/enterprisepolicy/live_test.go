// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The live checks run a real client binary. These tests re-execute the
// test binary as a fake Codex app-server or Claude Code CLI through a small
// wrapper script (the live environment is minimal, so the script carries
// the fake's settings).
func TestMain(m *testing.M) {
	switch os.Getenv("DC_FAKE_AGENT") {
	case "codex":
		fakeCodexAppServer()
		os.Exit(0)
	case "claude":
		os.Exit(fakeClaudeCLI())
	}
	os.Exit(m.Run())
}

func fakeCodexAppServer() {
	scanner := bufio.NewScanner(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)
	for scanner.Scan() {
		var request struct {
			ID     *int   `json:"id"`
			Method string `json:"method"`
		}
		if json.Unmarshal(scanner.Bytes(), &request) != nil || request.ID == nil {
			continue
		}
		var result any
		switch request.Method {
		case "initialize":
			result = map[string]any{"userAgent": "fake"}
		case "configRequirements/read":
			result = map[string]any{"requirements": map[string]any{"allowManagedHooksOnly": os.Getenv("DC_FAKE_LOCK") == "true"}}
		case "hooks/list":
			result = map[string]any{"data": []any{map[string]any{"hooks": []any{map[string]any{
				"command": os.Getenv("DC_FAKE_COMMAND"), "enabled": os.Getenv("DC_FAKE_ENABLED") == "true", "trusted": true,
			}}}}}
		}
		_ = encoder.Encode(map[string]any{"id": *request.ID, "result": result})
	}
}

func fakeClaudeCLI() int {
	base := os.Getenv("ANTHROPIC_BASE_URL")
	post := func(body string) (map[string]any, error) {
		response, err := http.Post(base+"/v1/messages", "application/json", strings.NewReader(body))
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		var decoded map[string]any
		return decoded, json.NewDecoder(response.Body).Decode(&decoded)
	}
	first, err := post(`{"messages":[{"role":"user","content":"go"}]}`)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	content, _ := first["content"].([]any)
	for _, raw := range content {
		block, _ := raw.(map[string]any)
		input, _ := block["input"].(map[string]any)
		command, _ := input["command"].(string)
		if command != "" && os.Getenv("DC_FAKE_HOOK_LOG") != "" {
			// Stand-in for DefenseClaw's managed PreToolUse hook reaching the gateway.
			file, err := os.OpenFile(os.Getenv("DC_FAKE_HOOK_LOG"), os.O_APPEND|os.O_WRONLY, 0o600)
			if err == nil {
				fmt.Fprintf(file, `{"event":"PreToolUse","command":%q}`+"\n", command)
				_ = file.Close()
			}
		}
	}
	if _, err := post(`{"messages":[{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_canary"}]}]}`); err != nil {
		return 1
	}
	fmt.Println(`{"result":"done"}`)
	return 0
}

func fakeAgentScript(t *testing.T, agent string, env map[string]string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("wrapper script is POSIX sh")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var script bytes.Buffer
	script.WriteString("#!/bin/sh\n")
	fmt.Fprintf(&script, "export DC_FAKE_AGENT=%s\n", shellQuote(agent))
	for key, value := range env {
		fmt.Fprintf(&script, "export %s=%s\n", key, shellQuote(value))
	}
	fmt.Fprintf(&script, "exec %s -test.run='^$' \"$@\"\n", shellQuote(self))
	path := filepath.Join(t.TempDir(), agent)
	if err := os.WriteFile(path, script.Bytes(), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestVerifyLiveCodexAppServer(t *testing.T) {
	opts := testOptions(t)
	home := t.TempDir()
	good := fakeAgentScript(t, "codex", map[string]string{"DC_FAKE_LOCK": "true", "DC_FAKE_ENABLED": "true", "DC_FAKE_COMMAND": codexHookCommandForEvent(opts, "PreToolUse")})
	result, err := VerifyLive(context.Background(), opts, LiveOptions{Connector: ConnectorCodex, AgentBinary: good, Home: home, Timeout: 30 * time.Second})
	if err != nil || !result.Verified || len(result.Evidence) != 2 {
		t.Fatalf("a locked client with trusted hooks must verify: %+v %v", result, err)
	}

	disabled := fakeAgentScript(t, "codex", map[string]string{"DC_FAKE_LOCK": "false", "DC_FAKE_ENABLED": "false", "DC_FAKE_COMMAND": codexHookCommandForEvent(opts, "PreToolUse")})
	result, err = VerifyLive(context.Background(), opts, LiveOptions{Connector: ConnectorCodex, AgentBinary: disabled, Home: home, Timeout: 30 * time.Second})
	if err != nil || result.Verified || result.HookContact != "no" || len(result.Problems) < 2 {
		t.Fatalf("an unlocked client with disabled hooks must fail: %+v %v", result, err)
	}
}

func TestVerifyLiveClaudeCanary(t *testing.T) {
	opts := testOptions(t)
	home := t.TempDir()
	log := filepath.Join(t.TempDir(), "gateway.jsonl")
	writeFile(t, log, "")
	hooked := fakeAgentScript(t, "claude", map[string]string{"DC_FAKE_HOOK_LOG": log})
	result, err := VerifyLive(context.Background(), opts, LiveOptions{Connector: ConnectorClaudeCode, AgentBinary: hooked, Home: home, GatewayLog: log, Timeout: 30 * time.Second})
	if err != nil || !result.Verified || result.HookContact != "yes" || !strings.Contains(readFile(t, log), result.Nonce) {
		t.Fatalf("a hooked run must reach the gateway: %+v %v", result, err)
	}

	shadowed := fakeAgentScript(t, "claude", map[string]string{})
	result, err = VerifyLive(context.Background(), opts, LiveOptions{Connector: ConnectorClaudeCode, AgentBinary: shadowed, Home: home, GatewayLog: log, Timeout: 30 * time.Second})
	if err != nil || result.Verified || result.HookContact != "no" || !strings.Contains(strings.Join(result.Problems, " "), "server-managed") {
		t.Fatalf("a run without DefenseClaw's hooks must fail and name the likely cause: %+v %v", result, err)
	}

	if _, err := VerifyLive(context.Background(), opts, LiveOptions{Connector: "cursor", AgentBinary: hooked, Home: home}); err == nil {
		t.Fatal("live verification is only implemented for codex and claudecode")
	}
}
