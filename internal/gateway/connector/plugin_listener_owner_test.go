// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
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
	program, err := hookListenerCheckProgram()
	if err != nil {
		t.Fatal(err)
	}
	return renderPluginBridgeWithListenerCheckForTest(t, asset, apiAddr, tokenPath, failMode, managed, program)
}

// renderPluginBridgeWithListenerCheckForTest renders asset with program as
// its DC_LISTENER_CHECK.
func renderPluginBridgeWithListenerCheckForTest(t *testing.T, asset, apiAddr, tokenPath, failMode string, managed bool, program string) string {
	t.Helper()
	tmpl, err := hookFS.ReadFile("hooks/" + asset)
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

// TestPluginBridgesRefuseEmptyListenerCheck pins that an OpenCode or Amp
// bridge whose listener check is empty on Linux or macOS refuses the request
// as unverifiable, as the OmniGent module does: `/bin/sh -c ""` exits 0, so
// running an empty check would send the bearer without verifying the
// listener. Nothing is sent, and the fail mode decides.
func TestPluginBridgesRefuseEmptyListenerCheck(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required")
	}
	dir := testenv.PrivateTempDir(t)
	nodeRunsTypeScript := false
	probe := filepath.Join(dir, "probe.ts")
	if err := os.WriteFile(probe, []byte("const x: number = 1\nconsole.log(x)\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(node, probe).CombinedOutput(); err == nil && strings.TrimSpace(string(out)) == "1" {
		nodeRunsTypeScript = true
	}
	own := trustedHookListenerAddr(t)
	for _, bridge := range []struct {
		name, asset, extension, harness string
		typeScript                      bool
	}{
		{name: "opencode", asset: "opencode-plugin.js", extension: ".mjs", harness: openCodeListenerHarness},
		{name: "amp", asset: "amp-plugin.ts", extension: ".ts", harness: ampListenerHarness, typeScript: true},
	} {
		for _, failMode := range []string{"closed", "open"} {
			t.Run(bridge.name+" fail "+failMode, func(t *testing.T) {
				if bridge.typeScript && !nodeRunsTypeScript {
					t.Skip("node cannot run TypeScript directly")
				}
				tokenPath := filepath.Join(dir, ".hook-"+bridge.name+".token")
				if err := os.WriteFile(tokenPath, []byte(strings.Repeat("c", 64)+"\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				harness := filepath.Join(dir, bridge.name+"-harness.mjs")
				if err := os.WriteFile(harness, []byte(bridge.harness), 0o600); err != nil {
					t.Fatal(err)
				}
				plugin := filepath.Join(dir, bridge.name+"-empty-check-"+failMode+bridge.extension)
				rendered := renderPluginBridgeWithListenerCheckForTest(t, bridge.asset, own, tokenPath, failMode, false, "")
				if err := os.WriteFile(plugin, []byte(rendered), 0o600); err != nil {
					t.Fatal(err)
				}
				want := pluginListenerScenario{name: "empty listener check", addr: own, failMode: failMode}
				if failMode == "closed" {
					want.wantBlocked = true
					want.wantReason = "cannot verify the owner of the gateway listener"
				}
				checkPluginScenario(t, want, runPluginHarness(t, node, harness, plugin))
			})
		}
	}
}

// omnigentListenerHarness imports a rendered OmniGent policy module, counts
// the requests it hands to its transport (which then fails), and prints the
// verdict as a pluginHarnessResult.
const omnigentListenerHarness = `
import importlib.util, json, sys
calls = 0
spec = importlib.util.spec_from_file_location("defenseclaw_omnigent_policy", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
def counting_open(request, *args, **kwargs):
    global calls
    calls += 1
    raise OSError("fixture transport")
module._DIRECT_OPENER.open = counting_open
verdict = module.defenseclaw_policy({"type": "request", "data": "hello"})
blocked = verdict.get("result") != "ALLOW"
print(json.dumps({"blocked": blocked, "reason": verdict.get("reason", ""), "calls": calls}))
`

// runOmnigentListenerHarness runs the harness against modulePath with the
// given interpreter command prefix and environment.
func runOmnigentListenerHarness(t *testing.T, prefix []string, env []string, modulePath string) pluginHarnessResult {
	t.Helper()
	args := append(append([]string{}, prefix[1:]...), "-c", omnigentListenerHarness, modulePath)
	cmd := exec.Command(prefix[0], args...)
	cmd.Env = env
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("execute policy: %v\n%s", err, output)
	}
	var got pluginHarnessResult
	if err := json.Unmarshal(output, &got); err != nil {
		t.Fatalf("policy output %q: %v", output, err)
	}
	return got
}

// omnigentExpectation adjusts a scenario for the harness transport: a
// request that is handed over then fails, so a closed module denies it.
func omnigentExpectation(sc pluginListenerScenario) pluginListenerScenario {
	if sc.wantCalls == 1 && sc.failMode == "closed" {
		sc.wantBlocked, sc.wantReason = true, "bridge error"
	}
	return sc
}

// TestOmnigentPolicyChecksGatewayListenerOwner runs the rendered OmniGent
// policy module: it sends the scoped bearer only after the hooks'
// listener-owner check accepts the gateway port. The enterprise guardian
// installs the module as a managed hook runtime, so the managed cases apply
// too. The module's process environment carries the opposite
// DEFENSECLAW_MANAGED_HOOK value: only the rendered setting may choose the
// trust set.
func TestOmnigentPolicyChecksGatewayListenerOwner(t *testing.T) {
	python := omnigentTestPython(t)
	templateBytes, err := hookFS.ReadFile("hooks/omnigent-policy.py")
	if err != nil {
		t.Fatal(err)
	}
	for _, sc := range pluginListenerScenarios(t, true) {
		t.Run(sc.name, func(t *testing.T) {
			root := t.TempDir()
			tokenPath := writeOmnigentScopedToken(t, filepath.Join(root, "dc"), strings.Repeat("c", 64))
			modulePath := filepath.Join(root, "defenseclaw_omnigent_policy.py")
			rendered := renderOmnigentPolicy(string(templateBytes), sc.addr, tokenPath, sc.failMode, sc.managed)
			if err := os.WriteFile(modulePath, []byte(rendered), 0o600); err != nil {
				t.Fatal(err)
			}
			inherited := "1"
			if sc.managed {
				inherited = "0"
			}
			env := []string{"PATH=/nonexistent", "HOME=" + root, "DEFENSECLAW_MANAGED_HOOK=" + inherited}
			checkPluginScenario(t, omnigentExpectation(sc), runOmnigentListenerHarness(t, []string{python}, env, modulePath))
		})
	}
}

// TestOmnigentSetupRendersManagedListenerTrust installs the module through
// Setup: a managed install (SetupOpts.ManagedEnterprise, as the enterprise
// guardian and a managed reconcile set it) refuses a listener the hook user
// owns, and a per-user install sends to it.
func TestOmnigentSetupRendersManagedListenerTrust(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root's own listener is the managed gateway; TestOmnigentPolicyManagedListenerAcrossAccounts covers root")
	}
	python := omnigentTestPython(t)
	if runtime.GOOS == "darwin" {
		if _, err := exec.LookPath("netstat"); err != nil {
			t.Skip("netstat is required")
		}
	}
	own := trustedHookListenerAddr(t)
	for _, sc := range []pluginListenerScenario{
		{name: "per-user", addr: own, failMode: "closed", wantCalls: 1},
		{name: "managed", addr: own, failMode: "closed", managed: true,
			wantBlocked: true, wantReason: "not the managed gateway"},
	} {
		t.Run(sc.name, func(t *testing.T) {
			root := t.TempDir()
			dataDir := filepath.Join(root, "defenseclaw")
			configPath := filepath.Join(root, ".omnigent", "config.yaml")
			sitePackages := filepath.Join(root, "venv", "site-packages")
			withOmnigentPathOverrides(t, configPath, sitePackages)
			if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(configPath, []byte("server: https://example.test\npolicy_modules: []\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(dataDir, 0o700); err != nil {
				t.Fatal(err)
			}
			conn := NewOmnigentConnector()
			if _, err := EnsureHookAPIToken(dataDir, conn.Name()); err != nil {
				t.Fatal(err)
			}
			opts := SetupOpts{
				DataDir:           dataDir,
				APIAddr:           sc.addr,
				APIToken:          strings.Repeat("d", 64),
				HookFailMode:      sc.failMode,
				ManagedEnterprise: sc.managed,
			}
			if err := conn.Setup(context.Background(), opts); err != nil {
				t.Fatalf("Setup: %v", err)
			}
			env := []string{"PATH=/nonexistent", "HOME=" + root}
			got := runOmnigentListenerHarness(t, []string{python}, env, omnigentPolicyModulePath(opts))
			checkPluginScenario(t, omnigentExpectation(sc), got)
		})
	}
}

// TestOmnigentPolicyManagedListenerAcrossAccounts runs the rendered module
// as an unprivileged account against listeners that other accounts own: a
// managed module sends to a root listener and, on Linux, to one the
// packaged defenseclaw service account owns (the managed gateway's User=),
// and refuses the hook user's own listener; a per-user module refuses the
// service account's listener. It needs root and DEFENSECLAW_TEST_OTHER_UID
// naming an unprivileged uid, so it runs on the disposable test hosts.
func TestOmnigentPolicyManagedListenerAcrossAccounts(t *testing.T) {
	other := os.Getenv("DEFENSECLAW_TEST_OTHER_UID")
	if other == "" || os.Geteuid() != 0 {
		t.Skip("requires root and DEFENSECLAW_TEST_OTHER_UID")
	}
	otherUID, err := strconv.Atoi(other)
	if err != nil || otherUID <= 0 {
		t.Fatalf("DEFENSECLAW_TEST_OTHER_UID=%q is not an unprivileged uid", other)
	}
	const python = "/usr/bin/python3"
	if _, err := os.Stat(python); err != nil {
		t.Skip("requires /usr/bin/python3")
	}
	if runtime.GOOS == "darwin" {
		if _, err := exec.LookPath("netstat"); err != nil {
			t.Skip("netstat is required")
		}
	}
	templateBytes, err := hookFS.ReadFile("hooks/omnigent-policy.py")
	if err != nil {
		t.Fatal(err)
	}
	// t.TempDir's parent is private to root; the module runs as another uid.
	dir, err := os.MkdirTemp("", "dc-omnigent-listener-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(dir, ".hook-omnigent.token")
	if err := os.WriteFile(tokenPath, []byte(strings.Repeat("c", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(tokenPath, otherUID, -1); err != nil {
		t.Fatal(err)
	}
	holdAs := func(account string) string {
		t.Helper()
		probe, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := probe.Addr().(*net.TCPAddr).Port
		_ = probe.Close()
		holder := exec.Command("/usr/bin/sudo", "-u", account, python, "-c",
			fmt.Sprintf(`import socket,time
s=socket.socket(); s.bind(("127.0.0.1",%d)); s.listen(1); print("up",flush=True); time.sleep(30)`, port))
		stdout, err := holder.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := holder.Start(); err != nil {
			t.Fatalf("start listener as %s: %v", account, err)
		}
		t.Cleanup(func() { _ = holder.Process.Kill(); _ = holder.Wait() })
		buf := make([]byte, 3)
		if _, err := stdout.Read(buf); err != nil {
			t.Fatalf("listener as %s did not start: %v", account, err)
		}
		return fmt.Sprintf("127.0.0.1:%d", port)
	}
	run := func(t *testing.T, i int, sc pluginListenerScenario) {
		t.Helper()
		modulePath := filepath.Join(dir, fmt.Sprintf("policy_%d.py", i))
		rendered := renderOmnigentPolicy(string(templateBytes), sc.addr, tokenPath, sc.failMode, sc.managed)
		if err := os.WriteFile(modulePath, []byte(rendered), 0o644); err != nil {
			t.Fatal(err)
		}
		prefix := []string{"/usr/bin/sudo", "-u", "#" + other, "/usr/bin/env", "-i",
			"PATH=/usr/bin:/bin", "HOME=" + dir, python}
		checkPluginScenario(t, omnigentExpectation(sc), runOmnigentListenerHarness(t, prefix, nil, modulePath))
	}

	rootListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer rootListener.Close()
	scenarios := []pluginListenerScenario{
		{name: "managed root listener", addr: rootListener.Addr().String(), failMode: "closed", managed: true, wantCalls: 1},
		{name: "managed hook user listener", addr: holdAs("#" + other), failMode: "closed", managed: true,
			wantBlocked: true, wantReason: "not the managed gateway"},
	}
	if runtime.GOOS == "linux" {
		if raw, err := exec.Command("/usr/bin/id", "-u", "defenseclaw").Output(); err == nil {
			service := strings.TrimSpace(string(raw))
			serviceAddr := holdAs("defenseclaw")
			scenarios = append(scenarios,
				pluginListenerScenario{name: "managed service account listener", addr: serviceAddr, failMode: "closed", managed: true, wantCalls: 1},
				pluginListenerScenario{name: "per-user service account listener", addr: serviceAddr, failMode: "closed",
					wantBlocked: true, wantReason: "held by " + service + ", not this user's gateway"},
			)
		} else {
			t.Log("no defenseclaw service account; service-account cases skipped")
		}
	}
	for i, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) { run(t, i, sc) })
	}
}
