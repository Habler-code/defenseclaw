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

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// evaluateWithin fails the test instead of hanging when the guard blocks.
func evaluateWithin(t *testing.T, req GuardRequest) GuardDecision {
	t.Helper()
	done := make(chan GuardDecision, 1)
	go func() { done <- EvaluateForeignHooks(req) }()
	select {
	case decision := <-done:
		return decision
	case <-time.After(10 * time.Second):
		t.Fatal("the guard blocked on a hook path")
		return GuardDecision{}
	}
}

// A FIFO or unreadable file named by a handler's command cannot be bound,
// so the handler cannot be approved, and naming it must not block the
// guard.
func TestGuardUnboundSpecialOrUnreadableReferences(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any file")
	}
	for name, setup := range map[string]func(path string) error{
		"fifo": func(path string) error { return syscall.Mkfifo(path, 0o600) },
		"unreadable": func(path string) error {
			if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
				return err
			}
			return os.Chmod(path, 0)
		},
	} {
		req := guardRequest(t, "cursor", config.ForeignHooksRemove)
		repo := filepath.Dir(req.WorkingDir)
		if err := setup(filepath.Join(repo, "check.sh")); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(repo, ".cursor", "hooks.json"), `{"version": 1, "hooks": {"preToolUse": [{"command": "bash check.sh"}]}}`)
		first := evaluateWithin(t, req)
		if !first.Deny || len(first.Findings) != 1 || !strings.HasPrefix(first.Findings[0].Reason, unapprovableReason) {
			t.Fatalf("%s: must deny as unapprovable: %+v", name, first)
		}
		req.Policy.AllowedHooks = []string{first.Findings[0].Digest}
		if decision := evaluateWithin(t, req); !decision.Deny {
			t.Fatalf("%s: an unapprovable finding must stay denied: %+v", name, decision)
		}
	}
}

// Node-based agents read a named pipe with fs.readFile and load whatever a
// writer sends. A FIFO (or any non-regular file) at a hook path cannot be
// verified, so it must deny instead of counting as absent, and the guard
// must not block opening it.
func TestGuardFailsClosedOnNonRegularHookPaths(t *testing.T) {
	for name, tc := range map[string]struct {
		connector string
		rel       func(req GuardRequest) string
	}{
		"project file":        {"cursor", func(req GuardRequest) string { return filepath.Join(req.WorkingDir, "..", ".cursor", "hooks.json") }},
		"user flat-dir entry": {"copilot", func(req GuardRequest) string { return filepath.Join(req.Home, ".copilot", "hooks", "a.json") }},
		"flat-dir itself":     {"copilot", func(req GuardRequest) string { return filepath.Join(req.WorkingDir, "..", ".github", "hooks") }},
		"plugin entry": {"opencode", func(req GuardRequest) string {
			return filepath.Join(req.Home, ".config", "opencode", "plugins", "x.js")
		}},
		"plugin dir itself": {"amp", func(req GuardRequest) string { return filepath.Join(req.WorkingDir, "..", ".amp", "plugins") }},
	} {
		req := guardRequest(t, tc.connector, config.ForeignHooksRemove)
		path := tc.rel(req)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
		decision := evaluateWithin(t, req)
		if !decision.Deny || !strings.Contains(decision.Reason, "cannot be verified") {
			t.Fatalf("%s: a FIFO at %s must fail closed: %+v", name, path, decision)
		}
	}

	req := guardRequest(t, "cursor", config.ForeignHooksRemove)
	userHooks := filepath.Join(req.Home, ".cursor", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(userHooks), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(userHooks, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := CleanUserForeignHooks(req, time.Now())
	if err != nil || len(result.Removed) != 0 || len(result.Reported) != 1 {
		t.Fatalf("cleanup must report, not remove or skip, a FIFO: %+v %v", result, err)
	}
}

// A home reached through a symlink (macOS temporary directories, some
// network homes) is still the home when the resolved working directory is
// walked: the walk stops there and each file is scanned once.
func TestGuardRecognizesAHomeBehindASymlink(t *testing.T) {
	real := filepath.Join(t.TempDir(), "real-home")
	if err := os.MkdirAll(filepath.Join(real, "scratch"), 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "home")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	req := guardRequest(t, "cursor", config.ForeignHooksRemove)
	req.Home = link
	req.WorkingDir = filepath.Join(link, "scratch")
	writeFile(t, filepath.Join(real, ".cursor", "hooks.json"), `{"version": 1, "hooks": {"preToolUse": [{"command": "./rewrite.sh"}]}}`)
	decision := EvaluateForeignHooks(req)
	if !decision.Deny || len(decision.Findings) != 1 || decision.Findings[0].Scope != ScopeUser {
		t.Fatalf("the home's hook file must be found once, as a user source: %+v", decision)
	}
}
