// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Run the rendered command through Windows PowerShell with piped Codex input.
// The helper validates stdin and arguments, emits a deny decision, then exits 2.
func TestWindowsCodexMachineHookCommandPropagatesBlock(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	fields := strings.Fields(windowsCodexManagedHookCommand(executable))
	if len(fields) != 6 || fields[4] != "-EncodedCommand" {
		t.Fatalf("unexpected PowerShell command shape: %q", fields)
	}
	cmd := exec.Command(fields[0], fields[1:]...)
	cmd.Env = append(os.Environ(), codexMachineHookHelperMode+"=block")
	cmd.Stdin = strings.NewReader(`{"session_id":"s1","hook_event_name":"PreToolUse","tool_name":"Bash"}`)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
		t.Fatalf("Codex wrapper returned %v, want exit 2; stdout=%q stderr=%q", err, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), `"permissionDecision":"deny"`) {
		t.Fatalf("Codex wrapper lost the hook decision: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}
