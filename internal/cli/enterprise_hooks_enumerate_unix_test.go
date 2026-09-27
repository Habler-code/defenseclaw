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
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
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

// The parent re-validated worker versions by re-extracting them, which
// stripped the trailing "v" of "1.2.0-dev" and dropped the version.
func TestEnumerateDiscoverKeepsPrereleaseVersionsEndingInV(t *testing.T) {
	origRunner := enterpriseHookWorkerRunner
	t.Cleanup(func() { enterpriseHookWorkerRunner = origRunner })
	enterpriseHookWorkerRunner = func(context.Context, enterpriseHookWorkerAccount, enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		return enterpriseHookWorkerResponse{Versions: map[string]string{"opencode": "1.2.0-dev", "amp": "v0.9.1", "codex": "$(id)"}}, nil
	}
	versions, _, err := enterpriseHooksEnumerateDiscover(context.Background(), unixidentity.Account{Name: "alice", UID: 1000, GID: 1000, Home: "/home/alice"}, []string{"opencode", "amp", "codex"})
	if err != nil {
		t.Fatal(err)
	}
	if versions["opencode"] != "1.2.0-dev" {
		t.Fatalf("a valid prerelease version was dropped: %v", versions)
	}
	if _, ok := versions["amp"]; ok {
		t.Fatalf("a non-canonical worker version must not be accepted: %v", versions)
	}
	if _, ok := versions["codex"]; ok {
		t.Fatalf("a forged worker version must be dropped: %v", versions)
	}
}

// A cycle publishes the unprotected agents beside the manifest, which is
// the record status and verify read. For a never-enrolled user whose home is
// untrusted the worker is asked for a static discovery only, and the agent
// found there is published too.
func TestEnumerateCyclePublishesTheUnprotectedAgentsRecord(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	alice := f.home(t, "alice", 0o700)
	resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: uid, GID: gid, Home: alice, Shell: "/bin/bash"}
	origLoader, origResolver, origSessions := enterpriseHooksEnumerateConfigLoader, enterpriseHooksEnumerateResolver, enterpriseHookSessionUIDs
	origManifestWriter, origEligibleWriter, origUnprotectedWriter := enterpriseHooksEnumerateManifestWriter, enterpriseHooksEnumerateEligibleWriter, enterpriseHooksEnumerateUnprotectedWriter
	t.Cleanup(func() {
		enterpriseHooksEnumerateConfigLoader, enterpriseHooksEnumerateResolver, enterpriseHookSessionUIDs = origLoader, origResolver, origSessions
		enterpriseHooksEnumerateManifestWriter, enterpriseHooksEnumerateEligibleWriter, enterpriseHooksEnumerateUnprotectedWriter = origManifestWriter, origEligibleWriter, origUnprotectedWriter
	})
	current := standaloneTestConfig(f.dataDir)
	current.Enterprise.Enrollment.IncludeUsers = []string{"alice"}
	current.Enterprise.Enrollment.HomeRoots = []string{f.homes}
	enabled := true
	current.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{"opencode": {Enabled: &enabled}}
	enterpriseHooksEnumerateConfigLoader = func() (*config.Config, error) { return current, nil }
	enterpriseHooksEnumerateResolver = func(context.Context) unixidentity.Resolver { return resolver }
	enterpriseHookSessionUIDs = func() []int { return nil }
	var requests []enterpriseHookWorkerRequest
	enterpriseHookWorkerRunner = func(_ context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		if request.Operation != enterpriseHookWorkerOpDiscover || account.Home != alice {
			return enterpriseHookWorkerResponse{}, fmt.Errorf("unexpected worker request %+v for %+v", request, account)
		}
		requests = append(requests, request)
		return enterpriseHookWorkerResponse{Reasons: map[string]string{
			"opencode": enterprisehooks.UnixAgentUnversionedReasonPrefix + filepath.Join(alice, ".local", "bin", "opencode"),
		}}, nil
	}
	enterpriseHooksEnumerateManifestWriter = func(string, enterprisehooks.Manifest) (bool, error) { return true, nil }
	enterpriseHooksEnumerateEligibleWriter = func(string, []enterprisehooks.UnixEligibleAccount) error { return nil }
	var recordPath string
	var recorded []enterprisehooks.UnprotectedAgent
	enterpriseHooksEnumerateUnprotectedWriter = func(path string, agents []enterprisehooks.UnprotectedAgent) error {
		recordPath, recorded = path, append([]enterprisehooks.UnprotectedAgent(nil), agents...)
		return nil
	}
	opts := enterpriseHooksEnumerateOptions{manifest: f.manifest, descriptor: filepath.Join(f.root, "absent.json")}
	cycle := func() {
		t.Helper()
		requests, recordPath, recorded = nil, "", nil
		state := &enterprisehooks.UnixEnumeratorState{Version: 1}
		if _, err := runEnterpriseHooksEnumerateCycle(context.Background(), io.Discard, f.manifest, opts, state); err != nil {
			t.Fatal(err)
		}
		if recordPath != enterprisehooks.UnprotectedAgentsPath(f.manifest) {
			t.Fatalf("record published at %q, want beside the manifest", recordPath)
		}
		if len(recorded) != 1 || recorded[0].User != "alice" || recorded[0].Connector != "opencode" {
			t.Fatalf("record = %+v, want alice's opencode", recorded)
		}
	}

	cycle()
	if len(requests) != 1 || requests[0].StaticDiscovery {
		t.Fatalf("worker requests = %+v, want one executing discovery for a trusted home", requests)
	}
	if err := os.Chmod(alice, 0o775); err != nil {
		t.Fatal(err)
	}
	cycle()
	if len(requests) != 1 || !requests[0].StaticDiscovery {
		t.Fatalf("worker requests = %+v, want one static discovery for an untrusted home", requests)
	}
	if !strings.Contains(recorded[0].Reason, "untrusted home") {
		t.Fatalf("reason %q must name the untrusted home", recorded[0].Reason)
	}
}
