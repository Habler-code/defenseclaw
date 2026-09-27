// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

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

// The Amp plugin must be a module Amp's runtime can load: a template that
// does not parse leaves every Amp session without DefenseClaw. Node strips
// the TypeScript types the way Bun does; the harness then registers the
// plugin against a minimal plugin API and lists the handlers it installed.
// Both the per-user render and the Windows standalone render (foreign-hook
// guard, install marker and listener proof) are loaded.
func TestAmpPluginTemplateLoadsAndRegistersEveryEvent(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is required for the Amp plugin load test")
	}
	root := testenv.PrivateTempDir(t)
	tmpl, err := hookFS.ReadFile("hooks/amp-plugin.ts")
	if err != nil {
		t.Fatal(err)
	}
	harness := `
import { pathToFileURL } from "node:url";
const loaded = await import(pathToFileURL(process.argv[1]).href);
const handlers = {};
loaded.default({
  system: { workspaceRoot: "", executor: { kind: "" }, user: {} },
  helpers: { filePathFromURI: (uri) => uri, isPluginUINotAvailableError: () => true },
  on: (event, handler) => { handlers[event] = typeof handler; },
  activeThread: { current: null },
  ui: { notify: async () => {} },
});
console.log(JSON.stringify(Object.keys(handlers).sort().map((event) => event + ":" + handlers[event])));
`
	want := `["agent.end:function","agent.start:function","session.start:function","tool.call:function","tool.result:function"]`
	for name, data := range map[string]templateData{
		"per-user": {
			APIAddr:     "127.0.0.1:18970",
			TokenFileJS: javaScriptStringContent(filepath.Join(root, ".hook-amp.token")),
			FailMode:    "open",
		},
		"windows standalone": {
			APIAddr:            "127.0.0.1:18970",
			TokenFileJS:        javaScriptStringContent(filepath.Join(root, ".hook-amp.token")),
			ForeignHookGuardJS: javaScriptStringContent(filepath.Join(root, "missing", "defenseclaw-hook.exe")),
			InstallMarkerJS:    javaScriptStringContent(filepath.Join(root, "DefenseClaw-HookRuntime")),
			ListenerProofJS:    "1",
			FailMode:           "closed",
			Managed:            true,
		},
	} {
		rendered, err := renderTemplate(string(tmpl), data)
		if err != nil {
			t.Fatalf("%s: render: %v", name, err)
		}
		path := filepath.Join(root, strings.ReplaceAll(name, " ", "-")+".mts")
		if err := os.WriteFile(path, []byte(rendered), 0o600); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		cmd := exec.CommandContext(ctx, node, "--input-type=module", "-e", harness, path)
		var stderr strings.Builder
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		cancel()
		if err != nil {
			t.Fatalf("%s: the Amp plugin did not load: %v; stderr=%s", name, err, stderr.String())
		}
		if got := strings.TrimSpace(string(out)); got != want {
			t.Fatalf("%s: registered handlers %s, want %s", name, got, want)
		}
	}
}
