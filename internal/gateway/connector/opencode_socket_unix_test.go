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
