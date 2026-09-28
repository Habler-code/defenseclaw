// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// openCodePluginHarness loads a rendered OpenCode plugin with a stub TUI
// client, applies its config hook, runs tool.execute.before `calls` times and
// prints one verdict per call, then the toasts it showed.
const openCodePluginHarness = `
import { pathToFileURL } from "node:url";
const toasts = [];
const client = { tui: { showToast: async (arg) => { toasts.push(arg && arg.body ? arg.body : arg); return true; } } };
const href = pathToFileURL(process.argv[1]).href;
const loaded = await import(href);
const plugin = await loaded.DefenseClaw({ directory: "", client });
await plugin.config({ plugin_origins: [{ spec: href }], mcp: {} });
for (let i = 0; i < Number(process.argv[2]); i++) {
  try {
    await plugin["tool.execute.before"]({ tool: "bash", sessionID: "S", messageID: "M", callID: "C" + i }, { args: { command: "echo marker" } });
    console.log("allow");
  } catch (error) {
    console.log("block:" + String(error && error.message || error));
  }
}
await new Promise((resolve) => setTimeout(resolve, 50));
console.log("toasts:" + JSON.stringify(toasts));
`

func runOpenCodePluginHarness(t *testing.T, data templateData, calls int) []string {
	t.Helper()
	return runOpenCodePluginAssetHarness(t, "opencode-plugin.js", data, calls)
}

func runOpenCodePluginAssetHarness(t *testing.T, asset string, data templateData, calls int) []string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for the OpenCode plugin test")
	}
	rendered := renderPluginAssetForTest(t, asset, data)
	path := filepath.Join(testenv.PrivateTempDir(t), "defenseclaw.mjs")
	if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, node, "--input-type=module", "-e", openCodePluginHarness, path, strconv.Itoa(calls)).CombinedOutput()
	if err != nil {
		t.Fatalf("node: %v\n%s", err, out)
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n")
}

const (
	openCodeGatewayBlock   = `{"action":"block","mode":"action","severity":"CRITICAL","reason":"matched: CERT-MARKER","hook_output":{"decision":"deny","reason":"matched: CERT-MARKER"}}`
	openCodeGatewayConfirm = `{"action":"alert","raw_action":"confirm","mode":"action","severity":"HIGH","reason":"matched: REVIEW-MARKER"}`
)

// OpenCode shows a plugin block as the tool's error and hands it to the
// model, so the error says DefenseClaw blocked the call under policy and that
// it did not run; a bare rule reason read like tool output and the model
// reported success. A confirm (human-in-the-loop) verdict, which this bridge
// cannot ask about, shows a visible notice instead of running silently.
func TestOpenCodePluginBlockAndConfirmAreVisible(t *testing.T) {
	server := openCodeStubGateway(t, openCodeGatewayBlock, openCodeGatewayConfirm)
	lines := runOpenCodePluginHarness(t, openCodePluginTestData(t, server), 2)
	if len(lines) != 3 {
		t.Fatalf("harness output = %q", lines)
	}
	if want := "block:DefenseClaw blocked this tool call under policy, so it did not run: matched: CERT-MARKER"; lines[0] != want {
		t.Fatalf("block = %q, want %q", lines[0], want)
	}
	if lines[1] != "allow" {
		t.Fatalf("a confirm verdict still runs the call here: %q", lines[1])
	}
	var toasts []struct {
		Message string `json:"message"`
		Variant string `json:"variant"`
	}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(lines[2], "toasts:")), &toasts); err != nil {
		t.Fatalf("toasts %q: %v", lines[2], err)
	}
	if len(toasts) != 1 || toasts[0].Variant != "warning" ||
		!strings.HasPrefix(toasts[0].Message, "DefenseClaw flagged this tool call for review (HIGH): matched: REVIEW-MARKER.") {
		t.Fatalf("confirm notice = %+v", toasts)
	}
}

// A reason that already starts with DefenseClaw (fail-closed and credential
// failures) is shown as is.
func TestOpenCodePluginKeepsDefenseClawReasons(t *testing.T) {
	server := openCodeStubGateway(t, `{"action":"block","mode":"action","hook_output":{"decision":"deny","reason":"DefenseClaw blocked the command under policy."}}`)
	lines := runOpenCodePluginHarness(t, openCodePluginTestData(t, server), 1)
	if len(lines) != 2 || lines[0] != "block:DefenseClaw blocked the command under policy." || lines[1] != "toasts:[]" {
		t.Fatalf("harness output = %q", lines)
	}
}

// The Secure Client render keeps its pinned behavior.
func TestOpenCodePluginSecureClientRenderKeepsItsText(t *testing.T) {
	server := openCodeStubGateway(t, openCodeGatewayBlock, openCodeGatewayConfirm)
	data := openCodePluginTestData(t, server)
	data.Managed = true
	lines := runOpenCodePluginAssetHarness(t, secureClientPluginAssets["opencode-plugin.js"], data, 2)
	if len(lines) != 3 || lines[0] != "block:matched: CERT-MARKER" || lines[1] != "allow" || lines[2] != "toasts:[]" {
		t.Fatalf("harness output = %q", lines)
	}
}
