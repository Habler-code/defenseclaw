// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// openCodeStubGateway answers the plugin's load heartbeat with allow and each
// tool call with the next response.
func openCodeStubGateway(t *testing.T, responses ...string) *httptest.Server {
	t.Helper()
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload struct {
			Event string `json:"hook_event_name"`
		}
		_ = json.Unmarshal(body, &payload)
		w.Header().Set("Content-Type", "application/json")
		if payload.Event != "tool.execute.before" {
			_, _ = io.WriteString(w, `{"action":"allow","mode":"action"}`)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if len(responses) == 0 {
			_, _ = io.WriteString(w, `{"action":"allow","mode":"action"}`)
			return
		}
		_, _ = io.WriteString(w, responses[0])
		responses = responses[1:]
	}))
	t.Cleanup(server.Close)
	return server
}

// renderOpenCodePluginTemplate renders the current OpenCode plugin template
// the way Setup does.
func renderOpenCodePluginTemplate(t *testing.T, data templateData) string {
	t.Helper()
	return renderPluginAssetForTest(t, "opencode-plugin.js", data)
}

// renderPluginAssetForTest renders one embedded plugin template.
func renderPluginAssetForTest(t *testing.T, asset string, data templateData) string {
	t.Helper()
	tmpl, err := hookFS.ReadFile("hooks/" + asset)
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := renderTemplate(string(tmpl), data)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rendered, "{{") {
		t.Fatal("rendered plugin retains a template action")
	}
	return rendered
}

func openCodePluginTestData(t *testing.T, server *httptest.Server) templateData {
	t.Helper()
	root := testenv.PrivateTempDir(t)
	token := filepath.Join(root, ".hook-opencode.token")
	if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return templateData{
		APIAddr:     strings.TrimPrefix(server.URL, "http://"),
		TokenFileJS: javaScriptStringContent(token),
		FailMode:    "closed",
	}
}
