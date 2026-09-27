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
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// TestOpenCodePluginForeignGuardStopsFailingClosedOnceTheDeploymentIsRemoved:
// uninstall removes the administrator-owned hook binary the foreign-hook
// guard runs, together with the install marker. A plugin left in a signed-out
// user's profile must then stop failing closed at the guard as well as at the
// gateway call; while the marker exists, a guard that cannot run still blocks.
func TestOpenCodePluginForeignGuardStopsFailingClosedOnceTheDeploymentIsRemoved(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for the OpenCode plugin guard test")
	}
	root := testenv.PrivateTempDir(t)
	installed := filepath.Join(root, "installed-HookRuntime")
	if err := os.MkdirAll(installed, 0o700); err != nil {
		t.Fatal(err)
	}
	removed := filepath.Join(root, "removed-HookRuntime")
	missingGuard := filepath.Join(root, "bin", "defenseclaw-hook")
	tokenPath := filepath.Join(root, "opencode.token")
	if err := os.WriteFile(tokenPath, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	unreachable := listener.Addr().String()
	_ = listener.Close()

	tmpl, err := hookFS.ReadFile("hooks/opencode-plugin.js")
	if err != nil {
		t.Fatal(err)
	}
	render := func(name, marker string) string {
		t.Helper()
		rendered, err := renderTemplate(string(tmpl), templateData{
			APIAddr:            unreachable,
			TokenFileJS:        javaScriptStringContent(tokenPath),
			ForeignHookGuardJS: javaScriptStringContent(missingGuard),
			InstallMarkerJS:    javaScriptStringContent(marker),
			FailMode:           "closed",
			Managed:            true,
		})
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	harness := `
import { pathToFileURL } from "node:url";
for (const path of process.argv.slice(1)) {
  const loaded = await import(pathToFileURL(path).href);
  const plugin = await loaded.DefenseClaw({ directory: "" });
  try {
    await plugin["tool.execute.before"](
      { tool: "Bash", sessionID: "S", messageID: "M", callID: "C" },
      { args: { command: "printf marker" } },
    );
    console.log("allow");
  } catch (error) {
    console.log("block:" + String(error && error.message || error));
  }
}
`
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, node, "--input-type=module", "-e", harness,
		render("installed.mjs", installed), render("removed.mjs", removed), render("unmarked.mjs", "")).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 3 {
		t.Fatalf("verdicts = %q, want three", out)
	}
	if !strings.HasPrefix(lines[0], "block:DefenseClaw could not check for unapproved plugins") {
		t.Fatalf("installed deployment with an unrunnable guard = %q, want the guard block", lines[0])
	}
	if lines[1] != "allow" {
		t.Fatalf("uninstalled deployment (guard binary and marker gone) = %q, want allow", lines[1])
	}
	if !strings.HasPrefix(lines[2], "block:DefenseClaw could not check for unapproved plugins") {
		t.Fatalf("plugin without a marker = %q, want the guard block", lines[2])
	}
}
