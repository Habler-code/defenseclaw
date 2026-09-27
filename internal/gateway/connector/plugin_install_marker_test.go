// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

func TestManagedPluginInstallMarkerRequiresAManagedAbsolutePath(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "DefenseClaw-HookRuntime")
	if got := managedPluginInstallMarker(SetupOpts{ManagedEnterprise: true, ManagedInstallMarker: marker + string(filepath.Separator)}); got != marker {
		t.Fatalf("managed marker = %q, want %q", got, marker)
	}
	for _, opts := range []SetupOpts{
		{ManagedInstallMarker: marker},
		{ManagedEnterprise: true, ManagedInstallMarker: "DefenseClaw-HookRuntime"},
		{ManagedEnterprise: true},
	} {
		if got := managedPluginInstallMarker(opts); got != "" {
			t.Fatalf("marker for %+v = %q, want none", opts, got)
		}
	}
}

// Both in-agent plugins carry the rendered marker, and an unmanaged render
// leaves it empty so their fail mode stays unconditional.
func TestPluginTemplatesRenderTheInstallMarker(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "Cisco", "DefenseClaw-HookRuntime")
	for _, asset := range []string{"opencode-plugin.js", "amp-plugin.ts"} {
		tmpl, err := hookFS.ReadFile("hooks/" + asset)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{marker, ""} {
			rendered, err := renderTemplate(string(tmpl), templateData{
				APIAddr:         "127.0.0.1:18970",
				TokenFileJS:     javaScriptStringContent(filepath.Join(t.TempDir(), "token")),
				InstallMarkerJS: javaScriptStringContent(value),
				FailMode:        "closed",
				Managed:         true,
			})
			if err != nil {
				t.Fatalf("render %s: %v", asset, err)
			}
			want := `DC_INSTALL_MARKER = "` + javaScriptStringContent(value) + `"`
			if asset == "amp-plugin.ts" {
				want = `DC_INSTALL_MARKER: string = "` + javaScriptStringContent(value) + `"`
			}
			if !strings.Contains(rendered, want) {
				t.Fatalf("%s rendered without %s", asset, want)
			}
		}
	}
}

// After an uninstall the OpenCode plugin stays in a signed-out user's profile
// with a closed fail mode. Once the gateway is unreachable or the credential
// is gone AND the administrator-owned install marker is gone, it must allow
// instead of blocking every tool call; while the marker exists it still fails
// closed, and a render without a marker never relaxes.
func TestOpenCodePluginStopsFailingClosedOnceTheDeploymentIsRemoved(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for the OpenCode plugin marker test")
	}
	root := testenv.PrivateTempDir(t)
	marker := filepath.Join(root, "DefenseClaw-HookRuntime")
	if err := os.MkdirAll(marker, 0o700); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(root, "opencode.token")
	writeToken := func() {
		t.Helper()
		if err := os.WriteFile(tokenPath, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	writeToken()
	// A port that was just released: nothing answers there.
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
	render := func(name, markerValue string) string {
		t.Helper()
		rendered, err := renderTemplate(string(tmpl), templateData{
			APIAddr:         unreachable,
			TokenFileJS:     javaScriptStringContent(tokenPath),
			InstallMarkerJS: javaScriptStringContent(markerValue),
			FailMode:        "closed",
			Managed:         true,
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
	withMarker := render("with-marker.mjs", marker)
	withoutMarker := render("without-marker.mjs", "")

	harness := `
import { pathToFileURL } from "node:url";
import { createInterface } from "node:readline";
const plugins = [];
for (const path of process.argv.slice(1)) {
  const loaded = await import(pathToFileURL(path).href);
  plugins.push(await loaded.DefenseClaw({ directory: "" }));
}
const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
for await (const line of lines) {
  const plugin = plugins[Number(line)];
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
	cmd := exec.CommandContext(ctx, node, "--input-type=module", "-e", harness, withMarker, withoutMarker)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
	})
	scanner := bufio.NewScanner(stdout)
	evaluate := func(step string, plugin int) string {
		t.Helper()
		if _, err := fmt.Fprintln(stdin, plugin); err != nil {
			t.Fatal(err)
		}
		if !scanner.Scan() {
			t.Fatalf("%s: read verdict: %v; stderr=%s", step, scanner.Err(), stderr.String())
		}
		return scanner.Text()
	}

	if got := evaluate("installed, gateway down", 0); !strings.HasPrefix(got, "block:DefenseClaw hook failed closed") {
		t.Fatalf("installed deployment with the gateway down = %q, want a fail-closed block", got)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	if got := evaluate("uninstalled, gateway gone", 0); got != "allow" {
		t.Fatalf("uninstalled deployment = %q, want allow", got)
	}
	if got := evaluate("no marker rendered", 1); !strings.HasPrefix(got, "block:DefenseClaw hook failed closed") {
		t.Fatalf("plugin without a marker = %q, want an unconditional fail-closed block", got)
	}
	if err := os.Remove(tokenPath); err != nil {
		t.Fatal(err)
	}
	if got := evaluate("uninstalled, credential gone", 0); got != "allow" {
		t.Fatalf("uninstalled deployment without a credential = %q, want allow", got)
	}
	if err := os.MkdirAll(marker, 0o700); err != nil {
		t.Fatal(err)
	}
	if got := evaluate("installed, credential gone", 0); got != "block:DefenseClaw hook credential is unavailable." {
		t.Fatalf("installed deployment without a credential = %q, want the credential block", got)
	}
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("OpenCode marker process: %v; stderr=%s", err, stderr.String())
	}
}
