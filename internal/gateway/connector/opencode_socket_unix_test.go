//go:build !windows

package connector

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestOpenCodeBridgeUsesVerifiedManagedHookSocket pins the standalone managed
// transport of the OpenCode bridge: with a hook socket configured the plugin
// posts over the unix socket without a bearer token, and it fails closed
// (without sending a byte) when the socket directory is owned by an account
// other than root or the gateway service account.
func TestOpenCodeBridgeUsesVerifiedManagedHookSocket(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for the executable OpenCode plugin contract")
	}
	body, err := hookFS.ReadFile("hooks/opencode-plugin.js")
	if err != nil {
		t.Fatal(err)
	}
	// Unix socket paths are length-limited; keep the directory short.
	root, err := os.MkdirTemp("/tmp", "dcoc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	runDir := filepath.Join(root, "run")
	if err := os.Mkdir(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(runDir, "hook.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var requests []*http.Request
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requests = append(requests, r.Clone(context.Background()))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"action": "block", "mode": "action",
			"hook_output": map[string]any{"decision": "deny", "reason": "blocked over the hook socket"},
		})
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	run := func(serviceUID int) string {
		t.Helper()
		text := strings.NewReplacer(
			"{{.APIAddr}}", "127.0.0.1:1",
			"{{.TokenFileJS}}", javaScriptStringContent(filepath.Join(root, "missing.token")),
			"{{.FailMode}}", "closed",
			"{{.HookSocketJS}}", javaScriptStringContent(socketPath),
			"{{.ServiceUID}}", strconv.Itoa(serviceUID),
			"{{.ForeignHookGuardJS}}", "",
			"{{.InstallMarkerJS}}", "",
			"{{.ListenerProofJS}}", "",
		).Replace(string(body))
		if strings.Contains(text, "{{.") {
			t.Fatal("rendered plugin retains a template placeholder")
		}
		plugin := filepath.Join(root, "plugin-"+strconv.Itoa(serviceUID)+".mjs")
		if err := os.WriteFile(plugin, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		script := `const m = await import(process.argv[1]);
const hooks = await m.DefenseClaw({ directory: "/tmp", worktree: "/tmp" });
try {
  await hooks["tool.execute.before"]({ tool: "bash", sessionID: "s", callID: "c" }, { args: { command: "echo hi" } });
  console.log("ALLOWED");
} catch (e) { console.log("THREW:" + e.message); }`
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, node, "--input-type=module", "-e", script, plugin).CombinedOutput()
		if err != nil {
			t.Fatalf("node harness: %v\n%s", err, out)
		}
		return strings.TrimSpace(string(out))
	}

	// The test's own uid owns the socket directory, standing in for the
	// gateway service account.
	got := run(os.Getuid())
	if !strings.Contains(got, "THREW:blocked over the hook socket") {
		t.Fatalf("trusted socket result = %q, want the gateway block reason", got)
	}
	mu.Lock()
	if len(requests) != 1 {
		t.Fatalf("hook socket requests = %d, want 1", len(requests))
	}
	if auth := requests[0].Header.Get("Authorization"); auth != "" {
		t.Fatalf("plugin sent a bearer token over the hook socket: %q", auth)
	}
	if path := requests[0].URL.Path; path != "/api/v1/opencode/hook" {
		t.Fatalf("hook socket path = %q", path)
	}
	mu.Unlock()

	// A socket owned by an account that is neither root nor the configured
	// service account is refused before any request is sent.
	got = run(os.Getuid() + 7)
	if os.Getuid() == 0 {
		t.Skip("running as root: root-owned directories are trusted")
	}
	if !strings.Contains(got, "THREW:DefenseClaw hook failed closed") || !strings.Contains(got, "not trusted") {
		t.Fatalf("untrusted socket result = %q, want a fail-closed refusal", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(requests) != 1 {
		t.Fatalf("untrusted socket received %d requests, want none beyond the first run", len(requests)-1)
	}
}

func TestManagedPluginHookSocketOnlyForManagedUnixInstalls(t *testing.T) {
	if socket, uid := managedPluginHookSocket(SetupOpts{ManagedHookSocket: "/run/defenseclaw-hook/hook.sock", ManagedServiceUID: 995}); socket != "" || uid != 0 {
		t.Fatalf("per-user install got socket %q uid %d, want TCP", socket, uid)
	}
	if socket, uid := managedPluginHookSocket(SetupOpts{ManagedEnterprise: true, ManagedHookSocket: "relative/hook.sock"}); socket != "" || uid != 0 {
		t.Fatalf("relative socket accepted: %q %d", socket, uid)
	}
	socket, uid := managedPluginHookSocket(SetupOpts{ManagedEnterprise: true, ManagedHookSocket: "/run/defenseclaw-hook/hook.sock", ManagedServiceUID: 995})
	if socket != "/run/defenseclaw-hook/hook.sock" || uid != 995 {
		t.Fatalf("managed socket = %q uid %d", socket, uid)
	}
	if _, uid := managedPluginHookSocket(SetupOpts{ManagedEnterprise: true, ManagedHookSocket: "/run/x.sock", ManagedServiceUID: -1}); uid != 0 {
		t.Fatalf("negative service uid = %d, want 0", uid)
	}
}

// fakeForeignHookGuard writes an executable standing in for the
// administrator-owned hook binary: it answers each --foreign-hook-check
// call with the next of answers (repeating the last) and records its
// arguments and request.
func fakeForeignHookGuard(t *testing.T, answers ...string) (string, string) {
	t.Helper()
	dir := t.TempDir()
	guard := filepath.Join(dir, "defenseclaw-hook")
	script := []string{"#!/bin/sh", "dir='" + dir + "'", `n=$(cat "$dir/count" 2>/dev/null || echo 0)`, `echo $((n + 1)) > "$dir/count"`, `cat > "$dir/request-$n"`, `echo "$*" > "$dir/args"`}
	for index, answer := range answers {
		condition := `[ "$n" -eq ` + strconv.Itoa(index) + ` ]`
		if index == len(answers)-1 {
			condition = "true"
		}
		script = append(script, "if "+condition+"; then printf '%s' '"+answer+"'; exit 0; fi")
	}
	if err := os.WriteFile(guard, []byte(strings.Join(script, "\n")+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return guard, dir
}

// The standalone OpenCode plugin calls the gateway directly, so it must run
// the administrator-owned foreign-hook guard itself: a denial (at load or
// per call) aborts the tool before any gateway contact, a denial at load
// holds for the process, and a guard that cannot run fails closed.
func TestOpenCodeBridgeRunsTheForeignHookGuard(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for the executable OpenCode plugin contract")
	}
	body, err := hookFS.ReadFile("hooks/opencode-plugin.js")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	requests := 0
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		requests++
		mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"hook_output": map[string]any{"decision": "allow"}})
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	root := t.TempDir()
	tokenPath := filepath.Join(root, ".hook-opencode.token")
	if err := os.WriteFile(tokenPath, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := func(guard string) string {
		t.Helper()
		text := strings.NewReplacer(
			"{{.APIAddr}}", listener.Addr().String(),
			"{{.TokenFileJS}}", javaScriptStringContent(tokenPath),
			"{{.FailMode}}", "closed",
			"{{.HookSocketJS}}", "",
			"{{.ServiceUID}}", "0",
			"{{.ForeignHookGuardJS}}", javaScriptStringContent(guard),
			"{{.InstallMarkerJS}}", "",
			"{{.ListenerProofJS}}", "",
		).Replace(string(body))
		plugin := filepath.Join(t.TempDir(), "plugin.mjs")
		if err := os.WriteFile(plugin, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		script := `const m = await import(process.argv[1]);
const hooks = await m.DefenseClaw({ directory: "/work/repo", worktree: "/work/repo" });
for (const call of ["c1", "c2"]) {
  try {
    await hooks["tool.execute.before"]({ tool: "bash", sessionID: "s", callID: call }, { args: { command: "echo hi" } });
    console.log("ALLOWED");
  } catch (e) { console.log("THREW:" + e.message); }
}`
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, node, "--input-type=module", "-e", script, plugin).CombinedOutput()
		if err != nil {
			t.Fatalf("node harness: %v\n%s", err, out)
		}
		return strings.TrimSpace(string(out))
	}

	deny, dir := fakeForeignHookGuard(t, `{"deny":true,"reason":"enterprise_foreign_hook_blocked: The project file /work/repo/.opencode/plugins/x.js adds a plugin"}`)
	got := run(deny)
	if strings.Count(got, "THREW:enterprise_foreign_hook_blocked") != 2 {
		t.Fatalf("a denying guard must abort every call: %q", got)
	}
	args, _ := os.ReadFile(filepath.Join(dir, "args"))
	request, _ := os.ReadFile(filepath.Join(dir, "request-0"))
	if !strings.Contains(string(args), "hook --connector opencode --foreign-hook-check") || !strings.Contains(string(request), `"cwd":"/work/repo"`) {
		t.Fatalf("guard invocation: args=%q request=%q", args, request)
	}

	sticky, _ := fakeForeignHookGuard(t, `{"deny":true,"reason":"blocked at load"}`, `{"deny":false}`)
	if got := run(sticky); strings.Count(got, "THREW:blocked at load") != 2 {
		t.Fatalf("a denial at load must hold for the process: %q", got)
	}

	allow, _ := fakeForeignHookGuard(t, `{"deny":false}`)
	if got := run(allow); strings.Count(got, "ALLOWED") != 2 {
		t.Fatalf("an allowing guard lets calls through: %q", got)
	}
	for name, guard := range map[string]string{
		"missing binary":   filepath.Join(root, "missing-guard"),
		"malformed answer": func() string { g, _ := fakeForeignHookGuard(t, `not json`); return g }(),
		"no deny field":    func() string { g, _ := fakeForeignHookGuard(t, `{}`); return g }(),
	} {
		if got := run(guard); strings.Count(got, "THREW:") != 2 {
			t.Fatalf("%s: the guard must fail closed: %q", name, got)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if requests != 2 {
		t.Fatalf("only the allowed calls reach the gateway: %d requests", requests)
	}
}
