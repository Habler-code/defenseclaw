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
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestPublishVerifyRemoveAll(t *testing.T) {
	withHigherSources(t)
	opts := testOptions(t)
	opts = withPolicy(opts, "copilot", func(p *config.EnterpriseConnectorPolicy) { p.Ownership = "off" })
	connectors := []string{"cursor", "Codex", "claudecode", "copilot", "devin", "geminicli", "kiro"}
	result, err := Publish(opts, connectors)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"claudecode", "codex", "cursor"}; !reflect.DeepEqual(result.MachinePolicyConnectors, want) {
		t.Fatalf("machine policy connectors = %v, want %v", result.MachinePolicyConnectors, want)
	}
	routes := map[string]string{}
	for _, state := range result.States {
		routes[state.Connector] = state.Route
	}
	if routes["devin"] != RoutePerUser || routes["geminicli"] != RouteUnsupported || routes["kiro"] != RouteACP || routes["copilot"] != RouteUnsupported {
		t.Fatalf("routes: %v", routes)
	}
	if !result.Complete() {
		t.Fatalf("publish should be complete: %+v", result.States)
	}
	summary, err := ParsePublicPolicy([]byte(readFile(t, opts.PublicPolicyPath)))
	if err != nil || !summary.Connectors["devin"].Guard || summary.Connectors["codex"].Guard {
		t.Fatalf("public summary: %v %+v", err, summary)
	}
	verify, err := VerifyAll(opts, connectors)
	if err != nil || !verify.Complete() {
		t.Fatalf("verify: %v %+v", err, verify.States)
	}
	if again, err := Publish(opts, connectors); err != nil || again.Changed {
		t.Fatalf("second publish must be a no-op: %v", err)
	}
	if _, err := RemoveAll(opts); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"etc/codex/requirements.toml", "etc/claude-code/managed-settings.d/90-defenseclaw.json", "etc/cursor/hooks.json", "etc/defenseclaw/machine-policy.json"} {
		if _, err := os.Stat(filepath.Join(opts.Root, rel)); !os.IsNotExist(err) {
			t.Errorf("%s must be removed: %v", rel, err)
		}
	}
	for _, rel := range []string{"etc/codex", "etc/cursor", "etc/claude-code/managed-settings.d"} {
		if _, err := os.Stat(filepath.Join(opts.Root, rel)); !os.IsNotExist(err) {
			t.Errorf("directory %s created by DefenseClaw must be removed when empty: %v", rel, err)
		}
	}
}

func TestTrustChecksRejectWritableAncestors(t *testing.T) {
	opts := testOptions(t)
	opts.SkipTrustChecks = false
	previous := trustedOwner
	uid := uint32(os.Getuid())
	trustedOwner = func(owner uint32) bool { return owner == uid }
	t.Cleanup(func() { trustedOwner = previous })
	if err := os.Chmod(opts.Root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := (codexTarget{}).Reconcile(opts); err != nil {
		t.Fatalf("trusted tree must be writable: %v", err)
	}
	etc := filepath.Join(opts.Root, "etc")
	if err := os.Chmod(etc, 0o777); err != nil {
		t.Fatal(err)
	}
	syscall.Umask(0o022)
	_, err := codexTarget{}.Reconcile(opts)
	if err == nil || !strings.Contains(err.Error(), "group/other-writable") {
		t.Fatalf("a world-writable ancestor must be refused, got %v", err)
	}
}
