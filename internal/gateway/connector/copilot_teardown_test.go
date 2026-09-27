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
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// Copilot loads every *.json in its hooks directory, and
// ~/.copilot/hooks/defenseclaw.json is DefenseClaw's own file. Teardown (the
// managed uninstall runs it for every enrolled user) must neither create it
// for a user who never had it nor leave it behind as an empty document; an
// earlier teardown left "{}" there for every test user.
func TestCopilotTeardownLeavesNoDefenseClawHooksFileBehind(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	dataDir := filepath.Join(dir, ".defenseclaw")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	testenv.SetHome(t, home)
	copilotHome := filepath.Join(home, ".copilot")
	t.Setenv("COPILOT_HOME", copilotHome)
	prevHooks, prevWorkspace := CopilotHooksPathOverride, CopilotWorkspaceDirOverride
	CopilotHooksPathOverride, CopilotWorkspaceDirOverride = "", ""
	t.Cleanup(func() { CopilotHooksPathOverride, CopilotWorkspaceDirOverride = prevHooks, prevWorkspace })

	hooks := filepath.Join(copilotHome, "hooks", "defenseclaw.json")
	opts := SetupOpts{DataDir: dataDir, APIAddr: "127.0.0.1:18970", APIToken: "tok-test"}
	teardown := func(step string) {
		t.Helper()
		if err := NewCopilotConnector().Teardown(context.Background(), opts); err != nil {
			t.Fatalf("%s: teardown: %v", step, err)
		}
	}
	absent := func(step string) {
		t.Helper()
		if _, err := os.Lstat(hooks); !errors.Is(err, os.ErrNotExist) {
			body, _ := os.ReadFile(hooks)
			t.Fatalf("%s: %s remains (%v): %q", step, hooks, err, body)
		}
	}

	teardown("user without Copilot hooks")
	absent("user without Copilot hooks")

	if err := os.MkdirAll(filepath.Dir(hooks), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, leftover := range []string{"{}\n", "{\n  \"version\": 1\n}\n", "{\"version\":1,\"hooks\":{}}\n"} {
		if err := os.WriteFile(hooks, []byte(leftover), 0o600); err != nil {
			t.Fatal(err)
		}
		teardown("empty leftover " + leftover)
		absent("empty leftover " + leftover)
	}

	if err := NewCopilotConnector().Setup(context.Background(), opts); err != nil {
		t.Fatalf("setup: %v", err)
	}
	teardown("after setup")
	absent("after setup")

	// An operator handler added to DefenseClaw's file survives teardown.
	if err := NewCopilotConnector().Setup(context.Background(), opts); err != nil {
		t.Fatalf("second setup: %v", err)
	}
	var document map[string]any
	body, err := os.ReadFile(hooks)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	events, _ := document["hooks"].(map[string]any)
	list, _ := events["preToolUse"].([]any)
	events["preToolUse"] = append(list, map[string]any{"type": "command", "bash": "/usr/local/bin/operator-review.sh"})
	body, _ = json.Marshal(document)
	if err := os.WriteFile(hooks, body, 0o600); err != nil {
		t.Fatal(err)
	}
	teardown("operator handler")
	kept, err := os.ReadFile(hooks)
	if err != nil {
		t.Fatalf("operator handler: teardown removed the file: %v", err)
	}
	if !strings.Contains(string(kept), "operator-review.sh") || strings.Contains(string(kept), "copilot-hook") {
		t.Fatalf("operator handler: teardown left %s", kept)
	}
}
