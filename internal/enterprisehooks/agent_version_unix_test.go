// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Hermes prints its version on stderr when stdout is not a terminal; the
// enumerator reported "no hermes installation found" for an installed agent.
func TestExecUnixAgentVersionFallsBackToStderr(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "hermes")
	body := "#!/bin/sh\necho \"Hermes Agent v0.21.5+2581.g74dc4ac (2026.9.24)\" >&2\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := execUnixAgentVersion(context.Background(), script, dir, ""); got != "0.21.5+2581.g74dc4ac" {
		t.Fatalf("version = %q", got)
	}
	stdout := filepath.Join(dir, "codex")
	if err := os.WriteFile(stdout, []byte("#!/bin/sh\necho codex-cli 0.157.1\necho noise 9.9.9 >&2\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := execUnixAgentVersion(context.Background(), stdout, dir, ""); got != "0.157.1" {
		t.Fatalf("stdout version must win: %q", got)
	}
}

// Hermes needs a writable state directory even for --version, and the
// enumerator sees homes read-only; the probe relocates its state into a
// private scratch directory that is removed afterwards.
func TestExecUnixAgentVersionGivesStatefulAgentsAScratchDir(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "scratch-path")
	script := filepath.Join(dir, "hermes")
	body := "#!/bin/sh\n[ -n \"$HERMES_HOME\" ] && touch \"$HERMES_HOME/lock\" || exit 1\necho \"$HERMES_HOME\" > " + marker + "\necho \"Hermes Agent v0.21.5\"\n"
	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := execUnixAgentVersion(context.Background(), script, dir, "HERMES_HOME"); got != "0.21.5" {
		t.Fatalf("version = %q", got)
	}
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	scratch := strings.TrimSpace(string(data))
	if scratch == "" || strings.HasPrefix(scratch, dir) {
		t.Fatalf("scratch dir = %q", scratch)
	}
	if _, err := os.Stat(scratch); !os.IsNotExist(err) {
		t.Fatalf("scratch dir %s was not removed", scratch)
	}
}

// OpenHands needs about 11 s to answer --version; its uv tool environment
// names the version without running it.
func TestDiscoverUnixAgentVersionReadsUVToolMetadata(t *testing.T) {
	home := t.TempDir()
	dist := filepath.Join(home, ".local", "share", "uv", "tools", "openhands", "lib", "python3.12", "site-packages", "openhands-1.16.0.dist-info")
	if err := os.MkdirAll(dist, 0o755); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(filepath.Dir(dist), "openhands_sdk-1.21.0.dist-info")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	if got, reason := DiscoverUnixAgentVersion(context.Background(), home, "openhands", false); got != "1.16.0" {
		t.Fatalf("version = %q (%s)", got, reason)
	}
}
