// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package connector

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// pluginListenerScenario is one run of a plugin bridge against the live
// socket table. calls counts the policy requests the bridge handed to fetch
// (or, for OmniGent, the gateway received).
type pluginListenerScenario struct {
	name        string
	addr        string
	failMode    string
	managed     bool
	wantCalls   int
	wantBlocked bool
	wantReason  string
}

// pluginListenerScenarios returns the owner-check cases every plugin bridge
// must honor: a per-user bridge sends to its own user's listener; nothing is
// sent to a port nobody listens on (the fail mode decides); a managed bridge
// never sends to a listener the hook user owns.
func pluginListenerScenarios(t *testing.T, managedSupported bool) []pluginListenerScenario {
	t.Helper()
	if runtime.GOOS == "darwin" {
		if _, err := exec.LookPath("netstat"); err != nil {
			t.Skip("netstat is required")
		}
	}
	own := trustedHookListenerAddr(t)
	closedListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := closedListener.Addr().String()
	_ = closedListener.Close()
	scenarios := []pluginListenerScenario{
		{name: "per-user own listener", addr: own, failMode: "closed", wantCalls: 1},
		{name: "nothing listening fail closed", addr: closed, failMode: "closed", wantBlocked: true, wantReason: "gateway unreachable"},
		{name: "nothing listening fail open", addr: closed, failMode: "open"},
	}
	if managedSupported && os.Geteuid() != 0 {
		scenarios = append(scenarios, pluginListenerScenario{
			name: "managed hook user listener", addr: own, failMode: "closed", managed: true,
			wantBlocked: true, wantReason: "not the managed gateway",
		})
	}
	return scenarios
}

func renderPluginBridgeForTest(t *testing.T, asset, apiAddr, tokenPath, failMode string, managed bool) string {
	t.Helper()
	tmpl, err := hookFS.ReadFile("hooks/" + asset)
	if err != nil {
		t.Fatal(err)
	}
	program, err := hookListenerCheckProgram()
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := renderTemplate(string(tmpl), templateData{
		APIAddr:         apiAddr,
		TokenFileJS:     javaScriptStringContent(tokenPath),
		ListenerCheckJS: javaScriptStringContent(program),
		FailMode:        failMode,
		Managed:         managed,
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rendered, "{{") {
		t.Fatalf("rendered %s retains a template action", asset)
	}
	return rendered
}

type pluginHarnessResult struct {
	Blocked bool   `json:"blocked"`
	Reason  string `json:"reason"`
	Calls   int    `json:"calls"`
}

func runPluginHarness(t *testing.T, node, harness, plugin string) pluginHarnessResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, harness, plugin)
	// The bridges must not depend on the caller's PATH or environment for
	// the listener check.
	cmd.Env = []string{"PATH=/nonexistent", "HOME=" + filepath.Dir(plugin)}
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("plugin harness: %v\n%s", err, output)
	}
	var result pluginHarnessResult
	if err := json.Unmarshal(output, &result); err != nil {
		t.Fatalf("plugin harness output %q: %v", output, err)
	}
	return result
}

func checkPluginScenario(t *testing.T, sc pluginListenerScenario, got pluginHarnessResult) {
	t.Helper()
	if got.Calls != sc.wantCalls {
		t.Fatalf("policy requests sent = %d, want %d (result %+v)", got.Calls, sc.wantCalls, got)
	}
	if got.Blocked != sc.wantBlocked {
		t.Fatalf("blocked = %v, want %v (result %+v)", got.Blocked, sc.wantBlocked, got)
	}
	if sc.wantReason != "" && !strings.Contains(got.Reason, sc.wantReason) {
		t.Fatalf("reason = %q, want it to contain %q", got.Reason, sc.wantReason)
	}
}

const openCodeListenerHarness = `
import { pathToFileURL } from "node:url";
let calls = 0;
globalThis.fetch = async (_url, init) => {
  const payload = JSON.parse(init && init.body || "{}");
  if (payload.hook_event_name === "tool.execute.before") calls++;
  return { ok: true, status: 200, async json() { return { hook_output: { decision: "allow" } }; } };
};
const loaded = await import(pathToFileURL(process.argv[2]).href);
const plugin = await loaded.DefenseClaw({ directory: "" });
let blocked = false;
let reason = "";
try {
  await plugin["tool.execute.before"](
    { tool: "Bash", sessionID: "S", messageID: "M", callID: "C" },
    { args: { command: "printf test" } },
  );
} catch (error) {
  blocked = true;
  reason = String(error && error.message || error);
}
console.log(JSON.stringify({ blocked, reason, calls }));
`

// TestOpenCodePluginChecksGatewayListenerOwner runs the rendered OpenCode
// bridge: it sends the scoped bearer only after the hooks' listener-owner
// check accepts the gateway port.
func TestOpenCodePluginChecksGatewayListenerOwner(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required")
	}
	dir := testenv.PrivateTempDir(t)
	tokenPath := filepath.Join(dir, ".hook-opencode.token")
	if err := os.WriteFile(tokenPath, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	harness := filepath.Join(dir, "harness.mjs")
	if err := os.WriteFile(harness, []byte(openCodeListenerHarness), 0o600); err != nil {
		t.Fatal(err)
	}
	for i, sc := range pluginListenerScenarios(t, true) {
		t.Run(sc.name, func(t *testing.T) {
			plugin := filepath.Join(dir, "opencode-"+string(rune('a'+i))+".mjs")
			rendered := renderPluginBridgeForTest(t, "opencode-plugin.js", sc.addr, tokenPath, sc.failMode, sc.managed)
			if err := os.WriteFile(plugin, []byte(rendered), 0o600); err != nil {
				t.Fatal(err)
			}
			checkPluginScenario(t, sc, runPluginHarness(t, node, harness, plugin))
		})
	}
}

const ampListenerHarness = `
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
globalThis.Bun = {
  file(path) {
    return { slice() { return { async text() { return readFileSync(path, "utf8"); } }; } };
  },
};
let calls = 0;
globalThis.fetch = async (_url, init) => {
  const payload = JSON.parse(init && init.body || "{}");
  if (payload.hook_event_name === "tool.call") calls++;
  return { ok: true, status: 200, async json() { return { action: "allow" }; } };
};
const handlers = {};
const amp = {
  on(name, handler) { handlers[name] = handler; },
  system: {},
  helpers: { filePathFromURI: (uri) => uri, isPluginUINotAvailableError: () => false },
  activeThread: { current: null },
  ui: { async notify() {} },
};
const loaded = await import(pathToFileURL(process.argv[2]).href);
loaded.default(amp);
const ctx = {
  thread: { async agent() { return { definition: { kind: "mode", mode: "smart" } }; } },
  ui: { async confirm() { return false; } },
};
const result = await handlers["tool.call"](
  { thread: { id: "T" }, toolUseID: "U", tool: "Bash", input: { command: "printf test" } },
  ctx,
);
const blocked = result.action !== "allow";
console.log(JSON.stringify({ blocked, reason: blocked ? String(result.message || "") : "", calls }));
`

// TestAmpPluginChecksGatewayListenerOwner runs the rendered Amp bridge under
// Node's type stripping with a Bun file shim: it sends the scoped bearer only
// after the hooks' listener-owner check accepts the gateway port.
func TestAmpPluginChecksGatewayListenerOwner(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required")
	}
	dir := testenv.PrivateTempDir(t)
	probe := filepath.Join(dir, "probe.ts")
	if err := os.WriteFile(probe, []byte("const x: number = 1\nconsole.log(x)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(node, probe).CombinedOutput(); err != nil || strings.TrimSpace(string(out)) != "1" {
		t.Skipf("node cannot run TypeScript directly: %v %s", err, out)
	}
	tokenPath := filepath.Join(dir, ".hook-amp.token")
	if err := os.WriteFile(tokenPath, []byte(strings.Repeat("b", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	harness := filepath.Join(dir, "harness.mjs")
	if err := os.WriteFile(harness, []byte(ampListenerHarness), 0o600); err != nil {
		t.Fatal(err)
	}
	for i, sc := range pluginListenerScenarios(t, true) {
		t.Run(sc.name, func(t *testing.T) {
			plugin := filepath.Join(dir, "amp-"+string(rune('a'+i))+".ts")
			rendered := renderPluginBridgeForTest(t, "amp-plugin.ts", sc.addr, tokenPath, sc.failMode, sc.managed)
			if err := os.WriteFile(plugin, []byte(rendered), 0o600); err != nil {
				t.Fatal(err)
			}
			checkPluginScenario(t, sc, runPluginHarness(t, node, harness, plugin))
		})
	}
}

// TestOmnigentPolicyChecksGatewayListenerOwner runs the rendered OmniGent
// policy module: it sends the scoped bearer only after the hooks'
// listener-owner check accepts the gateway port. OmniGent has no managed
// install, so only the per-user cases apply.
func TestOmnigentPolicyChecksGatewayListenerOwner(t *testing.T) {
	python := omnigentTestPython(t)
	templateBytes, err := hookFS.ReadFile("hooks/omnigent-policy.py")
	if err != nil {
		t.Fatal(err)
	}
	script := `
import importlib.util, json, socket, sys
calls = 0
spec = importlib.util.spec_from_file_location("defenseclaw_omnigent_policy", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
real_open = module._DIRECT_OPENER.open
def counting_open(request, *args, **kwargs):
    global calls
    calls += 1
    raise OSError("fixture transport")
module._DIRECT_OPENER.open = counting_open
verdict = module.defenseclaw_policy({"type": "request", "data": "hello"})
blocked = verdict.get("result") != "ALLOW"
print(json.dumps({"blocked": blocked, "reason": verdict.get("reason", ""), "calls": calls}))
`
	for i, sc := range pluginListenerScenarios(t, false) {
		t.Run(sc.name, func(t *testing.T) {
			root := t.TempDir()
			tokenPath := writeOmnigentScopedToken(t, filepath.Join(root, "dc"), strings.Repeat("c", 64))
			modulePath := filepath.Join(root, "defenseclaw_omnigent_policy.py")
			rendered := renderOmnigentPolicy(string(templateBytes), sc.addr, tokenPath, sc.failMode)
			if err := os.WriteFile(modulePath, []byte(rendered), 0o600); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(python, "-c", script, modulePath)
			cmd.Env = []string{"PATH=/nonexistent", "HOME=" + root}
			output, err := cmd.Output()
			if err != nil {
				t.Fatalf("execute policy %d: %v\n%s", i, err, output)
			}
			var got pluginHarnessResult
			if err := json.Unmarshal(output, &got); err != nil {
				t.Fatalf("policy output %q: %v", output, err)
			}
			want := sc
			if want.wantCalls == 1 {
				// The fixture transport fails after the request is handed
				// over, so the closed mode denies it.
				want.wantBlocked, want.wantReason = true, "bridge error"
			}
			checkPluginScenario(t, want, got)
		})
	}
}
