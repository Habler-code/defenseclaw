// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// Only a managed plugin that asks for the listener proof and keeps the TCP
// transport renders it; a unix hook socket verifies its owner instead.
func TestManagedPluginListenerProofOnlyForManagedTCPPlugins(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "hook.sock")
	for _, tc := range []struct {
		name string
		opts SetupOpts
		want bool
	}{
		{"managed TCP plugin", SetupOpts{ManagedEnterprise: true, ManagedListenerProof: true}, true},
		{"not requested", SetupOpts{ManagedEnterprise: true}, false},
		{"unmanaged", SetupOpts{ManagedListenerProof: true}, false},
		// Windows keeps TCP even when a socket is named.
		{"hook socket", SetupOpts{ManagedEnterprise: true, ManagedListenerProof: true, ManagedHookSocket: socket}, runtime.GOOS == "windows"},
	} {
		if got := managedPluginListenerProof(tc.opts); got != tc.want {
			t.Errorf("%s: listener proof = %v, want %v", tc.name, got, tc.want)
		}
		want := ""
		if tc.want {
			want = "1"
		}
		if got := managedPluginListenerProofJS(tc.opts); got != want {
			t.Errorf("%s: rendered value = %q, want %q", tc.name, got, want)
		}
	}
}

// Both in-agent plugins render the switch, and an unmanaged or Secure Client
// render leaves it empty.
func TestPluginTemplatesRenderTheListenerProof(t *testing.T) {
	for _, asset := range []string{"opencode-plugin.js", "amp-plugin.ts"} {
		tmpl, err := hookFS.ReadFile("hooks/" + asset)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{"1", ""} {
			rendered, err := renderTemplate(string(tmpl), templateData{
				APIAddr:         "127.0.0.1:18970",
				TokenFileJS:     javaScriptStringContent(filepath.Join(t.TempDir(), "token")),
				ListenerProofJS: value,
				FailMode:        "closed",
				Managed:         true,
			})
			if err != nil {
				t.Fatalf("render %s: %v", asset, err)
			}
			want := `const DC_LISTENER_PROOF = "` + value + `";` + "\n"
			if asset == "amp-plugin.ts" {
				want = `const DC_LISTENER_PROOF: string = "` + value + `"` + "\n"
			}
			if !strings.Contains(rendered, want) {
				t.Fatalf("%s rendered without %q", asset, want)
			}
		}
	}
}

// listenerProofRequest is one request a test listener received.
type listenerProofRequest struct {
	method        string
	path          string
	authorization string
	body          string
}

type listenerProofRecorder struct {
	mu       sync.Mutex
	requests []listenerProofRequest
}

func (r *listenerProofRecorder) record(req *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, listenerProofRequest{
		method:        req.Method,
		path:          req.URL.Path,
		authorization: req.Header.Get("Authorization"),
		body:          string(body),
	})
}

func (r *listenerProofRecorder) snapshot() []listenerProofRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := append([]listenerProofRequest(nil), r.requests...)
	r.requests = nil
	return out
}

// newImpostorListener answers like a user-owned process holding the gateway
// port: an arbitrary "proof" and an allow verdict for every hook request.
func newImpostorListener(t *testing.T, recorder *listenerProofRecorder) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		recorder.record(req)
		switch req.URL.Path {
		case UserScopedListenerProofPath:
			w.Header().Set(UserScopedListenerProofHeader, strings.Repeat("0", 64))
			w.WriteHeader(http.StatusNoContent)
		case "/api/v1/amp/hook":
			_, _ = io.WriteString(w, `{"action":"allow"}`)
		default:
			_, _ = io.WriteString(w, `{"hook_output":{"decision":"allow"}}`)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

// newProvingListener answers like the gateway: it proves it can derive the
// plugin's credential (the same connector.UserScopedListenerProof the
// gateway's route uses) and accepts only that credential on the hook route.
func newProvingListener(t *testing.T, recorder *listenerProofRecorder, connectorName, credential string) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		recorder.record(req)
		if req.URL.Path == UserScopedListenerProofPath {
			if req.Method != http.MethodGet ||
				req.Header.Get("X-DefenseClaw-Connector") != connectorName ||
				req.Header.Get(UserScopedListenerKeyIDHeader) != UserScopedCredentialKeyID(credential) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			proof, err := UserScopedListenerProof(credential, connectorName, req.Header.Get(UserScopedListenerNonceHeader))
			if err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			w.Header().Set(UserScopedListenerProofHeader, proof)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if req.Header.Get("Authorization") != "Bearer "+credential {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if connectorName == "amp" {
			_, _ = io.WriteString(w, `{"action":"allow"}`)
			return
		}
		_, _ = io.WriteString(w, `{"hook_output":{"decision":"allow"}}`)
	}))
	t.Cleanup(server.Close)
	return server
}

const openCodeListenerProofHarness = `
import { pathToFileURL } from "node:url";
const loaded = await import(pathToFileURL(process.argv[1]).href);
const plugin = await loaded.DefenseClaw({ directory: "" });
try {
  await plugin["tool.execute.before"](
    { tool: "Bash", sessionID: "S", messageID: "M", callID: "C" },
    { args: { command: "printf listener-proof-marker" } },
  );
  console.log("allow");
} catch (error) {
  console.log("block:" + String(error && error.message || error));
}
`

// The Amp plugin runs under Bun, which provides Bun.file; the harness gives
// node the same small reader and a minimal plugin API.
const ampListenerProofHarness = `
import { pathToFileURL } from "node:url";
import { readFile } from "node:fs/promises";
globalThis.Bun = {
  file: (path) => ({ slice: (start, end) => ({ text: async () => (await readFile(path, "utf8")).slice(start, end) }) }),
};
const loaded = await import(pathToFileURL(process.argv[1]).href);
const handlers = {};
loaded.default({
  system: { workspaceRoot: "", executor: { kind: "" }, user: {} },
  helpers: { filePathFromURI: (uri) => uri, isPluginUINotAvailableError: () => true },
  on: (event, handler) => { handlers[event] = handler; },
  activeThread: { current: null },
  ui: { notify: async () => {} },
});
const result = await handlers["tool.call"](
  { thread: { id: "T" }, toolUseID: "U", tool: "Bash", input: { command: "printf listener-proof-marker" } },
  { thread: { agent: async () => { throw new Error("no agent"); } }, ui: { confirm: async () => false } },
);
console.log(result && result.action === "allow" ? "allow" : "block:" + String(result && result.message));
`

// runListenerProofPlugin renders asset against addr with the listener proof
// on or off, runs one pre-tool call in node, and returns its verdict.
func runListenerProofPlugin(t *testing.T, node, asset, addr, tokenPath string, proof bool) string {
	t.Helper()
	tmpl, err := hookFS.ReadFile("hooks/" + asset)
	if err != nil {
		t.Fatal(err)
	}
	proofValue := ""
	if proof {
		proofValue = "1"
	}
	rendered, err := renderTemplate(string(tmpl), templateData{
		APIAddr:         addr,
		TokenFileJS:     javaScriptStringContent(tokenPath),
		ListenerProofJS: proofValue,
		FailMode:        "closed",
		Managed:         true,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Each run is its own node process, so one file per plugin suffices.
	harness, name := openCodeListenerProofHarness, "opencode-plugin.mjs"
	if asset == "amp-plugin.ts" {
		harness, name = ampListenerProofHarness, "amp-plugin.mts"
	}
	path := filepath.Join(filepath.Dir(tokenPath), name)
	if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, node, "--input-type=module", "-e", harness, path)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s: node: %v; stderr=%s", asset, err, stderr.String())
	}
	return strings.TrimSpace(string(out))
}

// A Windows standalone plugin reaches the gateway over loopback TCP. A local
// user who holds the port while the gateway restarts must receive neither
// the user's credential nor the tool call, and must not be able to answer
// with a verdict: the plugin asks for the listener proof first, the
// impostor cannot produce it, and the tool call fails closed. The same
// plugin against a listener that can derive the credential proceeds.
// Without the proof the impostor receives the bearer and its allow is
// trusted, which is what the proof prevents.
func TestPluginListenerProofKeepsTheCredentialFromAnImpostor(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for the plugin listener proof test")
	}
	const key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	const sid = "S-1-5-21-1111-2222-3333-1001"
	for _, tc := range []struct {
		asset, connector, hookPath string
	}{
		{"opencode-plugin.js", "opencode", "/api/v1/opencode/hook"},
		{"amp-plugin.ts", "amp", "/api/v1/amp/hook"},
	} {
		t.Run(tc.connector, func(t *testing.T) {
			credential, err := UserScopedHookAPIToken(key, tc.connector, sid)
			if err != nil {
				t.Fatal(err)
			}
			root := testenv.PrivateTempDir(t)
			tokenPath := filepath.Join(root, ".hook-"+tc.connector+".token")
			if err := os.WriteFile(tokenPath, []byte(credential+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			impostorSeen := &listenerProofRecorder{}
			impostor := newImpostorListener(t, impostorSeen)
			addr := strings.TrimPrefix(impostor.URL, "http://")
			verdict := runListenerProofPlugin(t, node, tc.asset, addr, tokenPath, true)
			if !strings.HasPrefix(verdict, "block:DefenseClaw hook failed closed") ||
				!strings.Contains(verdict, "did not prove its identity") {
				t.Fatalf("impostor listener: verdict %q, want a fail-closed block", verdict)
			}
			requests := impostorSeen.snapshot()
			if len(requests) != 1 || requests[0].path != UserScopedListenerProofPath || requests[0].method != http.MethodGet {
				t.Fatalf("impostor must see only the proof request, saw %+v", requests)
			}
			if request := requests[0]; request.authorization != "" || request.body != "" ||
				strings.Contains(request.path, credential) {
				t.Fatalf("impostor received a credential or payload: %+v", request)
			}

			// Control: without the proof the impostor is trusted.
			verdict = runListenerProofPlugin(t, node, tc.asset, addr, tokenPath, false)
			requests = impostorSeen.snapshot()
			if verdict != "allow" || len(requests) != 1 || requests[0].authorization != "Bearer "+credential ||
				!strings.Contains(requests[0].body, "listener-proof-marker") {
				t.Fatalf("control without the proof: verdict %q, requests %+v", verdict, requests)
			}

			gatewaySeen := &listenerProofRecorder{}
			gateway := newProvingListener(t, gatewaySeen, tc.connector, credential)
			verdict = runListenerProofPlugin(t, node, tc.asset, strings.TrimPrefix(gateway.URL, "http://"), tokenPath, true)
			requests = gatewaySeen.snapshot()
			if verdict != "allow" || len(requests) != 2 ||
				requests[0].path != UserScopedListenerProofPath || requests[0].authorization != "" ||
				requests[1].path != tc.hookPath || requests[1].authorization != "Bearer "+credential {
				t.Fatalf("proving listener: verdict %q, requests %+v", verdict, requests)
			}
		})
	}
}

// A managed Amp plugin that must prove the listener fails verification when
// it was rendered before the proof existed, so the guardian repairs it; the
// same file with the proof on verifies. A plugin that needs no proof is
// unaffected.
func TestAMPManagedPluginVerificationRequiresTheListenerProof(t *testing.T) {
	root := testenv.PrivateTempDir(t)
	pluginPath := filepath.Join(root, ".config", "amp", "plugins", "defenseclaw.ts")
	previous := AMPPluginPathOverride
	AMPPluginPathOverride = pluginPath
	t.Cleanup(func() { AMPPluginPathOverride = previous })

	conn := NewAMPConnector()
	opts := prepareAmpSetupOptsForTest(t, SetupOpts{
		DataDir:  filepath.Join(root, "defenseclaw"),
		APIAddr:  "127.0.0.1:18970",
		APIToken: "amp-scoped-token",
	})
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	data, err := os.ReadFile(pluginPath)
	if err != nil {
		t.Fatal(err)
	}
	const off, on = `const DC_LISTENER_PROOF: string = ""` + "\n", `const DC_LISTENER_PROOF: string = "1"` + "\n"
	if !strings.Contains(string(data), off) {
		t.Fatal("a per-user render must leave the listener proof off")
	}
	if present, err := conn.ownedHookContractPresent(opts); err != nil || !present {
		t.Fatalf("a per-user plugin verifies without the proof: %v %v", present, err)
	}
	proving := opts
	proving.ManagedEnterprise = true
	proving.ManagedListenerProof = true
	if present, err := conn.ownedHookContractPresent(proving); err != nil || present {
		t.Fatalf("a plugin without the listener proof must fail verification: %v %v", present, err)
	}
	if err := os.WriteFile(pluginPath, []byte(strings.Replace(string(data), off, on, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if present, err := conn.ownedHookContractPresent(proving); err != nil || !present {
		t.Fatalf("a plugin carrying the listener proof verifies: %v %v", present, err)
	}
}

// The OpenCode plugin's verification likewise refuses a plugin rendered
// without the listener proof when the proof is required, and accepts the
// plugin the managed setup renders with it.
func TestOpenCodeManagedPluginVerificationRequiresTheListenerProof(t *testing.T) {
	for _, proof := range []bool{false, true} {
		dir := testenv.PrivateTempDir(t)
		pluginPath := filepath.Join(dir, ".config", "opencode", "plugins", "defenseclaw.js")
		previous := OpenCodePluginPathOverride
		OpenCodePluginPathOverride = pluginPath
		conn := NewOpenCodeConnector()
		opts := prepareOpenCodeSetupOptsForTest(t, SetupOpts{
			DataDir:  filepath.Join(dir, "dc"),
			APIAddr:  "127.0.0.1:18970",
			APIToken: "tok-opencode-listener-proof",
		})
		proving := opts
		proving.ManagedEnterprise = true
		proving.ManagedListenerProof = true
		rendered := opts
		if proof {
			rendered = proving
		}
		if err := conn.Setup(context.Background(), rendered); err != nil {
			OpenCodePluginPathOverride = previous
			t.Fatalf("Setup (proof %v): %v", proof, err)
		}
		data, err := os.ReadFile(pluginPath)
		if err != nil {
			OpenCodePluginPathOverride = previous
			t.Fatal(err)
		}
		want := `const DC_LISTENER_PROOF = "";` + "\n"
		if proof {
			want = `const DC_LISTENER_PROOF = "1";` + "\n"
		}
		present, verifyErr := OwnedHooksPresent(conn, proving)
		OpenCodePluginPathOverride = previous
		if !strings.Contains(string(data), want) {
			t.Fatalf("proof %v: plugin rendered without %q", proof, want)
		}
		if verifyErr != nil || present != proof {
			t.Fatalf("proof %v: verification requiring the proof = %v, %v; want %v", proof, present, verifyErr, proof)
		}
	}
}
