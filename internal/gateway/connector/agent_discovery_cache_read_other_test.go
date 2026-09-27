// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The agent discovery cache is in the user's data dir, so a privileged or
// shared reader must not block on a FIFO or allocate without bound there.
func TestLoadCachedAgentVersionRejectsNonRegularAndOversizedCache(t *testing.T) {
	const cache = `{"agents":{"codex":{"version":"codex-cli 0.142.0"}}}`
	writeCache := func(t *testing.T, data string) string {
		t.Helper()
		dataDir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dataDir, "agent_discovery.json"), []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		return dataDir
	}

	t.Run("regular file", func(t *testing.T) {
		if got := LoadCachedAgentVersion(writeCache(t, cache), "codex"); got != "codex-cli 0.142.0" {
			t.Fatalf("LoadCachedAgentVersion = %q, want the cached version", got)
		}
	})

	t.Run("symlink to a regular file", func(t *testing.T) {
		source := writeCache(t, cache)
		dataDir := t.TempDir()
		if err := os.Symlink(filepath.Join(source, "agent_discovery.json"), filepath.Join(dataDir, "agent_discovery.json")); err != nil {
			t.Fatal(err)
		}
		if got := LoadCachedAgentVersion(dataDir, "codex"); got != "codex-cli 0.142.0" {
			t.Fatalf("LoadCachedAgentVersion through a symlink = %q, want the cached version", got)
		}
	})

	t.Run("fifo", func(t *testing.T) {
		dataDir := t.TempDir()
		path := filepath.Join(dataDir, "agent_discovery.json")
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatalf("mkfifo: %v", err)
		}
		done := make(chan string, 1)
		go func() { done <- LoadCachedAgentVersion(dataDir, "codex") }()
		select {
		case got := <-done:
			if got != "" {
				t.Fatalf("LoadCachedAgentVersion on a FIFO = %q, want no version", got)
			}
		case <-time.After(5 * time.Second):
			// Release the blocked reader so the test process can finish.
			if writer, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
				_ = writer.Close()
			}
			<-done
			t.Fatal("LoadCachedAgentVersion blocked opening a FIFO agent discovery cache")
		}
	})

	t.Run("oversized", func(t *testing.T) {
		oversized := `{"agents":{"codex":{"version":"codex-cli 0.142.0"}},"padding":"` +
			strings.Repeat("x", agentDiscoveryCacheMaxBytes) + `"}`
		if got := LoadCachedAgentVersion(writeCache(t, oversized), "codex"); got != "" {
			t.Fatalf("LoadCachedAgentVersion on an oversized cache = %q, want no version", got)
		}
	})
}
