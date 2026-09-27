// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The managed (standalone enterprise) Kiro footprint is the user's global
// ~/.kiro/hooks file, which Kiro IDE and kiro-cli --v3 merge into every
// workspace, plus the CLI 2.x agent and its default-agent setting. The
// guardian passes the machine-wide workspace directory to every enrolled
// user; a managed install must not write a workspace copy there, which
// every user would share.
func TestKiroManagedSetupWritesOnlyTheUsersGlobalHooks(t *testing.T) {
	home := t.TempDir()
	workspace := t.TempDir()
	dataDir := t.TempDir()
	t.Cleanup(func() { KiroHomeOverride = "" })
	KiroHomeOverride = home

	opts := SetupOpts{
		DataDir:           dataDir,
		APIAddr:           "127.0.0.1:18970",
		APIToken:          "tok-test",
		WorkspaceDir:      workspace,
		HookFailMode:      "closed",
		ManagedEnterprise: true,
	}
	conn := NewKiroConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	global := filepath.Join(home, "hooks", kiroManagedHooksName)
	assertKiroV3Hooks(t, global, conn.hookCommandForV3Surface(opts))
	assertKiroV2AgentHooks(t, filepath.Join(home, "agents", kiroManagedAgentName+".json"), conn.hookCommand(opts))
	assertKiroDefaultAgentSetting(t, filepath.Join(home, "settings", "cli.json"))
	workspaceCopy := filepath.Join(workspace, ".kiro", "hooks", kiroManagedHooksName)
	if _, err := os.Stat(workspaceCopy); !os.IsNotExist(err) {
		t.Fatalf("managed Setup wrote the workspace copy %s (err=%v)", workspaceCopy, err)
	}

	caps := conn.HookCapabilities(opts)
	if caps.Scope != "user" || caps.ConfigPath != global {
		t.Fatalf("managed hook capability = scope %q path %q, want user %q", caps.Scope, caps.ConfigPath, global)
	}
	for _, path := range conn.AgentPaths(opts).PatchedFiles {
		if path == workspaceCopy {
			t.Fatalf("managed footprint lists the workspace copy %s", path)
		}
	}
	present, err := conn.ownedHookContractPresent(opts)
	if err != nil || !present {
		t.Fatalf("managed hook registration present = %v, %v", present, err)
	}

	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean: %v", err)
	}
}

// A managed install from an earlier build wrote the workspace copy too;
// teardown still reclaims it.
func TestKiroManagedTeardownReclaimsAnEarlierWorkspaceCopy(t *testing.T) {
	home := t.TempDir()
	workspace := t.TempDir()
	dataDir := t.TempDir()
	t.Cleanup(func() { KiroHomeOverride = "" })
	KiroHomeOverride = home

	perUser := SetupOpts{
		DataDir:      dataDir,
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "tok-test",
		WorkspaceDir: workspace,
		HookFailMode: "closed",
	}
	conn := NewKiroConnector()
	// The earlier managed footprint is the per-user one: it included the
	// workspace copy.
	if err := conn.Setup(context.Background(), perUser); err != nil {
		t.Fatalf("earlier Setup: %v", err)
	}
	workspaceCopy := filepath.Join(workspace, ".kiro", "hooks", kiroManagedHooksName)
	if _, err := os.Stat(workspaceCopy); err != nil {
		t.Fatalf("earlier Setup did not write the workspace copy: %v", err)
	}
	managed := perUser
	managed.ManagedEnterprise = true
	if err := conn.Teardown(context.Background(), managed); err != nil {
		t.Fatalf("managed Teardown: %v", err)
	}
	if err := conn.VerifyClean(managed); err != nil {
		t.Fatalf("managed VerifyClean: %v", err)
	}
	if _, err := os.Stat(workspaceCopy); !os.IsNotExist(err) {
		t.Fatalf("workspace copy left after teardown (err=%v)", err)
	}
}

// A per-user install keeps its footprint: the workspace copy and the
// workspace scope it has always reported.
func TestKiroPerUserFootprintIsUnchanged(t *testing.T) {
	home := t.TempDir()
	workspace := t.TempDir()
	t.Cleanup(func() { KiroHomeOverride = "" })
	KiroHomeOverride = home
	opts := SetupOpts{DataDir: t.TempDir(), WorkspaceDir: workspace}
	conn := NewKiroConnector()
	want := []string{
		filepath.Join(home, "hooks", kiroManagedHooksName),
		filepath.Join(workspace, ".kiro", "hooks", kiroManagedHooksName),
	}
	got := conn.hookConfigPaths(opts)
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("per-user hook paths = %v, want %v", got, want)
	}
	if scope := conn.HookCapabilities(opts).Scope; scope != "workspace" {
		t.Fatalf("per-user scope = %q, want workspace", scope)
	}
}

// A managed install never edits the user's own agents. With a custom
// chat.defaultAgent, it leaves that agent byte for byte and makes the
// defenseclaw agent the default instead, so bare kiro-cli still runs a
// hooked agent; teardown puts the user's setting back.
func TestKiroManagedSetupLeavesTheUsersDefaultAgentAlone(t *testing.T) {
	home := t.TempDir()
	dataDir := t.TempDir()
	t.Cleanup(func() { KiroHomeOverride = "" })
	KiroHomeOverride = home
	custom := filepath.Join(home, "agents", "mine.json")
	settings := filepath.Join(home, "settings", "cli.json")
	for path, body := range map[string]string{
		custom:   "{\n  \"name\": \"mine\",\n  \"tools\": [\"*\"]\n}\n",
		settings: "{\"chat.defaultAgent\": \"mine\"}\n",
	} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	customBefore, _ := os.ReadFile(custom)
	settingsBefore, _ := os.ReadFile(settings)

	opts := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "tok-test", HookFailMode: "closed", ManagedEnterprise: true}
	conn := NewKiroConnector()
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if after, _ := os.ReadFile(custom); string(after) != string(customBefore) {
		t.Fatalf("managed Setup edited the user's agent:\n%s", after)
	}
	assertKiroDefaultAgentSetting(t, settings)
	assertKiroV2AgentHooks(t, filepath.Join(home, "agents", kiroManagedAgentName+".json"), conn.hookCommand(opts))
	for _, path := range conn.AgentPaths(opts).PatchedFiles {
		if path == custom {
			t.Fatalf("managed footprint lists the user's agent %s", path)
		}
	}
	present, err := conn.ownedHookContractPresent(opts)
	if err != nil || !present {
		t.Fatalf("managed hook registration present = %v, %v", present, err)
	}

	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("Teardown: %v", err)
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("VerifyClean: %v", err)
	}
	if after, _ := os.ReadFile(custom); string(after) != string(customBefore) {
		t.Fatalf("managed teardown edited the user's agent:\n%s", after)
	}
	if after, _ := os.ReadFile(settings); string(after) != string(settingsBefore) {
		t.Fatalf("managed teardown did not restore the user's default agent: %s", after)
	}

	// A per-user install still guards the custom default agent itself.
	perUser := opts
	perUser.ManagedEnterprise = false
	if err := conn.Setup(context.Background(), perUser); err != nil {
		t.Fatalf("per-user Setup: %v", err)
	}
	if present, err := kiroV2AgentReferencesHook(custom, conn.hookCommand(perUser)); err != nil || !present {
		t.Fatalf("per-user Setup must still hook the custom default agent: %v %v", present, err)
	}
}
