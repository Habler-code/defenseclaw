// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// flakyForeignGuard is a stand-in for the administrator-owned hook binary
// whose foreign-hook check cannot run the first time (for example while an
// upgrade replaces it) and answers allow afterwards.
const flakyForeignGuard = `#!/bin/sh
cat >/dev/null
if [ ! -f "$0.ran" ]; then
  : > "$0.ran"
  echo "hook binary unavailable" >&2
  exit 1
fi
printf '{"deny":false}\n'
`

const startupGuardRestartText = "when the agent started (Command failed"

func writeFlakyForeignGuard(t *testing.T, root string) string {
	t.Helper()
	guard := filepath.Join(root, "defenseclaw-hook")
	if err := os.WriteFile(guard, []byte(flakyForeignGuard), 0o700); err != nil {
		t.Fatal(err)
	}
	return guard
}

// OpenCode and Amp load plugins once, so the foreign-plugin check at load
// is kept for the life of the process: a plugin loaded then keeps running
// even if its file is removed later. When that check itself fails, every
// later tool call stays blocked even once the check would succeed, so the
// reason says it failed when the agent started and to restart the agent.
func TestOpenCodePluginStartupGuardFailureSaysToRestart(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for the OpenCode plugin guard test")
	}
	root := testenv.PrivateTempDir(t)
	guard := writeFlakyForeignGuard(t, root)
	server := openCodeStubGateway(t)
	data := openCodePluginTestData(t, server)
	data.ForeignHookGuardJS = javaScriptStringContent(guard)
	data.Managed = true
	tmpl, err := hookFS.ReadFile("hooks/opencode-plugin.js")
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := renderTemplate(string(tmpl), data)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "defenseclaw.mjs")
	if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
		t.Fatal(err)
	}
	harness := `
import { pathToFileURL } from "node:url";
const href = pathToFileURL(process.argv[1]).href;
const loaded = await import(href);
const call = async (plugin, id) => {
  try {
    await plugin["tool.execute.before"]({ tool: "bash", sessionID: "S", messageID: "M", callID: id }, { args: { command: "echo marker" } });
    return "allow";
  } catch (error) {
    return "block:" + String(error && error.message || error);
  }
};
const first = await loaded.DefenseClaw({ directory: "", client: {} });
await first.config({ plugin_origins: [{ spec: href }], mcp: {} });
console.log(await call(first, "C1"));
console.log(await call(first, "C2"));
// A restarted agent loads the plugin again and checks again.
const restarted = await loaded.DefenseClaw({ directory: "", client: {} });
await restarted.config({ plugin_origins: [{ spec: href }], mcp: {} });
console.log(await call(restarted, "C3"));
`
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, node, "--input-type=module", "-e", harness, path).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 3 {
		t.Fatalf("verdicts = %q", lines)
	}
	for _, line := range lines[:2] {
		if !strings.HasPrefix(line, "block:DefenseClaw could not check for unapproved plugins "+startupGuardRestartText) ||
			!strings.HasSuffix(line, "Restart the agent once DefenseClaw is available.") {
			t.Fatalf("a failed load-time check must keep blocking and say to restart: %q", line)
		}
	}
	if lines[2] != "allow" {
		t.Fatalf("after a restart the check runs again: %q", lines[2])
	}
}

func TestAmpPluginStartupGuardFailureSaysToRestart(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for the Amp plugin guard test")
	}
	root := testenv.PrivateTempDir(t)
	guard := writeFlakyForeignGuard(t, root)
	tmpl, err := hookFS.ReadFile("hooks/amp-plugin.ts")
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := renderTemplate(string(tmpl), templateData{
		APIAddr:            "127.0.0.1:18970",
		TokenFileJS:        javaScriptStringContent(filepath.Join(root, ".hook-amp.token")),
		ForeignHookGuardJS: javaScriptStringContent(guard),
		FailMode:           "closed",
		Managed:            true,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "defenseclaw.mts")
	if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
		t.Fatal(err)
	}
	harness := `
import { pathToFileURL } from "node:url";
const loaded = await import(pathToFileURL(process.argv[1]).href);
const handlers = {};
loaded.default({
  system: { workspaceRoot: "", executor: { kind: "" }, user: {} },
  helpers: { filePathFromURI: (uri) => uri, isPluginUINotAvailableError: () => true },
  on: (event, handler) => { handlers[event] = handler; },
  activeThread: { current: null },
  ui: { notify: async () => {} },
});
for (const id of ["U1", "U2"]) {
  const result = await handlers["tool.call"]({ thread: { id: "T" }, toolUseID: id, tool: "Bash", input: {} }, {});
  console.log(result.action + ":" + (result.message || ""));
}
`
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, node, "--input-type=module", "-e", harness, path).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) != 2 {
		t.Fatalf("verdicts = %q", lines)
	}
	for _, line := range lines {
		if !strings.HasPrefix(line, "reject-and-continue:DefenseClaw could not check for unapproved plugins "+startupGuardRestartText) ||
			!strings.HasSuffix(line, "Restart the agent once DefenseClaw is available.") {
			t.Fatalf("a failed load-time check must keep blocking and say to restart: %q", line)
		}
	}
	if _, err := os.Stat(guard + ".ran"); err != nil {
		t.Fatalf("the guard ran at load: %v", err)
	}
}
