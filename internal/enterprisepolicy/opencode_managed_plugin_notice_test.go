// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// openCodeManagedNoticeHarness drives the managed plugin against the fake
// hook binary (openCodeFakeHook) and prints one line per step.
const openCodeManagedNoticeHarness = `
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
const [pluginPath, fakeDir] = process.argv.slice(2);
const answer = (file, stdout, exit = 0) => writeFileSync(join(fakeDir, file), JSON.stringify({ stdout, exit }));
let serial = 0;
const toasts = [];
const client = { tui: { showToast: async (arg) => { toasts.push(arg && arg.body ? arg.body : arg); return true; } } };
async function load() {
  serial += 1;
  const mod = await import(pathToFileURL(pluginPath).href + "?instance=" + serial);
  const hooks = await mod.DefenseClawManaged({ client, directory: "/work/repo", worktree: "/work/repo" });
  answer("event.json", JSON.stringify({ action: "allow", mode: "action" }));
  await hooks.config({ plugin_origins: [{ spec: pluginPath }], mcp: {} });
  return hooks;
}
async function before(hooks) {
  try {
    await hooks["tool.execute.before"]({ tool: "bash", sessionID: "s1", callID: "c1", messageID: "m1" }, { args: { command: "echo marker" } });
    return "allow";
  } catch (error) {
    return "block:" + String(error && error.message || error);
  }
}
if (process.argv[4] === "restart") {
  // The foreign-plugin check fails at load, then would succeed.
  answer("guard.json", "", 1);
  const hooks = await load();
  console.log(await before(hooks));
  answer("guard.json", JSON.stringify({ deny: false }));
  console.log(await before(hooks));
} else {
  // A gateway block, then a confirm verdict.
  answer("guard.json", JSON.stringify({ deny: false }));
  const hooks = await load();
  answer("event.json", JSON.stringify({ action: "block", mode: "action", hook_output: { decision: "deny", reason: "matched: CERT-MARKER" } }));
  console.log(await before(hooks));
  answer("event.json", JSON.stringify({ action: "alert", raw_action: "confirm", mode: "action", severity: "HIGH", reason: "matched: REVIEW-MARKER" }));
  console.log(await before(hooks));
  await new Promise((resolve) => setTimeout(resolve, 50));
  console.log("toasts:" + JSON.stringify(toasts));
}
`

// runOpenCodeManagedNoticeHarness runs one harness scenario against the
// shipped managed plugin and the fake hook binary.
func runOpenCodeManagedNoticeHarness(t *testing.T, scenario string) []string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the fake hook binary is a script")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	root := t.TempDir()
	plugin := filepath.Join(root, "share", "opencode", "defenseclaw.js")
	writeFile(t, plugin, string(OpenCodeManagedPlugin()))
	writeFile(t, filepath.Join(root, "share", "opencode", "package.json"), `{"type":"module"}`)
	hook := filepath.Join(root, "bin", "defenseclaw-hook")
	writeFile(t, hook, openCodeFakeHook)
	if err := os.Chmod(hook, 0o755); err != nil {
		t.Fatal(err)
	}
	fake := t.TempDir()
	harness := filepath.Join(t.TempDir(), "harness.mjs")
	writeFile(t, harness, openCodeManagedNoticeHarness)
	cmd := exec.Command(node, harness, plugin, fake, scenario)
	cmd.Env = append(os.Environ(), "DC_FAKE_DIR="+fake)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n")
}

// The managed OpenCode plugin keeps a failed load-time foreign-plugin check
// for the life of the process (OpenCode loads plugins once), so the reason
// says the check failed when the agent started and to restart the agent.
func TestOpenCodeManagedPluginStartupGuardFailureSaysToRestart(t *testing.T) {
	lines := runOpenCodeManagedNoticeHarness(t, "restart")
	const restart = "block:DefenseClaw could not check for unapproved plugins when the agent started (exit 1), so this tool call is blocked. Restart the agent once DefenseClaw is available."
	if len(lines) != 2 || lines[0] != restart || lines[1] != restart {
		t.Fatalf("a failed load-time check must keep blocking and say to restart: %q", lines)
	}
}

// A gateway block fails the tool call with an error that says DefenseClaw
// blocked it under the organization's policy and that it did not run; a
// confirm verdict shows a visible notice instead of running silently.
func TestOpenCodeManagedPluginBlockAndConfirmAreVisible(t *testing.T) {
	lines := runOpenCodeManagedNoticeHarness(t, "notice")
	if len(lines) != 3 {
		t.Fatalf("harness output = %q", lines)
	}
	if want := "block:DefenseClaw blocked this tool call under your organization's policy, so it did not run: matched: CERT-MARKER"; lines[0] != want {
		t.Fatalf("block = %q, want %q", lines[0], want)
	}
	if lines[1] != "allow" {
		t.Fatalf("a confirm verdict still runs the call: %q", lines[1])
	}
	if !strings.Contains(lines[2], `"variant":"warning"`) ||
		!strings.Contains(lines[2], "DefenseClaw flagged this tool call for review (HIGH): matched: REVIEW-MARKER.") {
		t.Fatalf("confirm notice = %q", lines[2])
	}
}
