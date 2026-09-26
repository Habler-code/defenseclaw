//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

func TestEnumerateCommandIsStandaloneOnlyAndIdlesInManifestMode(t *testing.T) {
	f := newStandaloneFixture(t, standaloneTestResolver{})
	origLoader := enterpriseHooksEnumerateConfigLoader
	t.Cleanup(func() { enterpriseHooksEnumerateConfigLoader = origLoader })
	current := standaloneTestConfig(f.dataDir)
	current.Enterprise.Enrollment.Mode = config.EnterpriseEnrollmentManifest
	enterpriseHooksEnumerateConfigLoader = func() (*config.Config, error) { return current, nil }
	var stdout bytes.Buffer
	opts := enterpriseHooksEnumerateOptions{manifest: f.manifest, jsonOut: true, dryRun: true}
	if err := runEnterpriseHooksEnumerate(context.Background(), &stdout, io.Discard, opts); err != nil {
		t.Fatal(err)
	}
	var report enterpriseHooksEnumerateReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil || !report.Idle {
		t.Fatalf("manifest mode must idle: %s (%v)", stdout.String(), err)
	}
	if err := runEnterpriseHooksEnumerate(context.Background(), io.Discard, io.Discard, enterpriseHooksEnumerateOptions{manifest: "relative.yaml"}); err == nil {
		t.Fatal("a relative manifest path must be refused")
	}
	cfg.Enterprise.Profile = managed.ProfileSecureClient
	if err := runEnterpriseHooksEnumerate(context.Background(), io.Discard, io.Discard, opts); err == nil || !strings.Contains(err.Error(), "standalone") {
		t.Fatalf("secure_client must not run the Unix enumerator: %v", err)
	}
}

func TestEnumerateCommandDryRunDiscoversThroughTheWorker(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	alice := f.home(t, "alice", 0o700)
	resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: uid, GID: gid, Home: alice, Shell: "/bin/bash"}
	origLoader, origResolver, origSessions := enterpriseHooksEnumerateConfigLoader, enterpriseHooksEnumerateResolver, enterpriseHookSessionUIDs
	t.Cleanup(func() {
		enterpriseHooksEnumerateConfigLoader, enterpriseHooksEnumerateResolver, enterpriseHookSessionUIDs = origLoader, origResolver, origSessions
	})
	current := standaloneTestConfig(f.dataDir)
	current.Enterprise.Enrollment.IncludeUsers = []string{"alice"}
	current.Enterprise.Enrollment.HomeRoots = []string{f.homes}
	enabled := true
	current.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"codex": {Enabled: &enabled}}
	enterpriseHooksEnumerateConfigLoader = func() (*config.Config, error) { return current, nil }
	enterpriseHooksEnumerateResolver = func(context.Context) unixidentity.Resolver { return resolver }
	enterpriseHookSessionUIDs = func() []int { return nil }
	enterpriseHookWorkerRunner = func(_ context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		if request.Operation != enterpriseHookWorkerOpDiscover || account.Home != alice {
			return enterpriseHookWorkerResponse{}, fmt.Errorf("unexpected worker request %+v for %+v", request, account)
		}
		// A forged, non-version answer must be dropped by the parent.
		return enterpriseHookWorkerResponse{Versions: map[string]string{"codex": "0.142.0", "cursor": "$(id)"}}, nil
	}
	var manifestOut bytes.Buffer
	opts := enterpriseHooksEnumerateOptions{manifest: f.manifest, dryRun: true, descriptor: filepath.Join(f.root, "absent.json")}
	if err := runEnterpriseHooksEnumerate(context.Background(), io.Discard, &manifestOut, opts); err != nil {
		t.Fatal(err)
	}
	out := manifestOut.String()
	if !strings.Contains(out, "user: alice") || !strings.Contains(out, "agent_version: 0.142.0") || strings.Contains(out, "$(id)") {
		t.Fatalf("dry-run manifest:\n%s", out)
	}
	if _, err := os.Stat(f.manifest); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("dry-run must not publish: %v", err)
	}
}
