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
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks/guardianstate"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

const enterpriseHookWorkerHelperEnv = "DEFENSECLAW_TEST_APPLY_TARGET_HELPER"

// TestEnterpriseHookWorkerHelperProcess is the apply-target worker body for
// the protocol tests. It does nothing when run as an ordinary test.
func TestEnterpriseHookWorkerHelperProcess(t *testing.T) {
	mode := os.Getenv(enterpriseHookWorkerHelperEnv)
	if mode == "" {
		return
	}
	if mode == "real" {
		// Root-only sentinel test: run the real installer and verifier.
		os.Exit(enterpriseHookWorkerMain(context.Background(), os.Stdin, os.Stdout, os.Stderr))
	}
	switch mode {
	case "garbage":
		fmt.Fprint(os.Stdout, "not json")
		os.Exit(0)
	case "oversize":
		_, _ = os.Stdout.Write(bytes.Repeat([]byte("x"), enterpriseHookWorkerResponseLimit+1))
		os.Exit(0)
	case "sleep":
		time.Sleep(time.Minute)
		os.Exit(0)
	}
	result := func(opts enterprisehooks.InstallOptions) enterprisehooks.InstallResult {
		// Report what the worker saw so the parent can assert on its
		// identity and environment.
		return enterprisehooks.InstallResult{
			Connector:      opts.ConnectorName,
			UserHome:       opts.UserHome,
			AgentVersion:   os.Getenv("HOME"),
			DataDir:        os.Getenv("DEFENSECLAW_TEST_LEAK"),
			HookContractID: os.Getenv(enterprisehooks.TrustedBinPrefixesEnv),
		}
	}
	enterpriseHookWorkerInstaller = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		if mode == "fail" {
			return enterprisehooks.InstallResult{}, errors.New("install refused")
		}
		return result(opts), nil
	}
	enterpriseHookWorkerVerifier = func(_ context.Context, opts enterprisehooks.InstallOptions) (enterprisehooks.InstallResult, error) {
		if mode == "drift" || mode == "fail" {
			return enterprisehooks.InstallResult{}, errors.New("hook config drifted")
		}
		return result(opts), nil
	}
	enterpriseHookWorkerDiscoverVersion = func(_ context.Context, home, connector string, allowExec bool) (string, string) {
		if connector == "codex" && allowExec {
			return "0.142.0", ""
		}
		return "", "not installed"
	}
	os.Exit(enterpriseHookWorkerMain(context.Background(), os.Stdin, os.Stdout, os.Stderr))
}

func useEnterpriseHookWorkerHelper(t *testing.T, mode string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("the helper worker runs as the invoking user; root cannot be a target")
	}
	origExe, origArgs, origEnv, origLog := enterpriseHookWorkerExecutable, enterpriseHookWorkerArgs, enterpriseHookWorkerExtraEnv, enterpriseHookWorkerLog
	t.Cleanup(func() {
		enterpriseHookWorkerExecutable, enterpriseHookWorkerArgs, enterpriseHookWorkerExtraEnv, enterpriseHookWorkerLog = origExe, origArgs, origEnv, origLog
	})
	enterpriseHookWorkerExecutable = os.Executable
	enterpriseHookWorkerArgs = []string{"-test.run=^TestEnterpriseHookWorkerHelperProcess$"}
	enterpriseHookWorkerExtraEnv = []string{enterpriseHookWorkerHelperEnv + "=" + mode}
	enterpriseHookWorkerLog = io.Discard
}

func selfWorkerAccount(t *testing.T) enterpriseHookWorkerAccount {
	t.Helper()
	return enterpriseHookWorkerAccount{UID: os.Getuid(), GID: os.Getgid(), User: "self", Home: filepath.Clean(t.TempDir())}
}

func workerTarget(account enterpriseHookWorkerAccount, index int, mode, connectorName string, previouslyProtected bool) enterpriseHookWorkerTarget {
	return enterpriseHookWorkerTarget{
		Index:               index,
		Mode:                mode,
		PreviouslyProtected: previouslyProtected,
		Options: enterpriseHookWorkerOptions{
			ConnectorName: connectorName,
			UserHome:      account.Home,
			OwnerUID:      account.UID,
			OwnerGID:      account.GID,
			APIToken:      "scoped-token",
		},
	}
}

func TestEnterpriseHookWorkerRunsTargetsWithAMinimalEnvironment(t *testing.T) {
	useEnterpriseHookWorkerHelper(t, "ok")
	t.Setenv("DEFENSECLAW_TEST_LEAK", "root-secret")
	t.Setenv(enterprisehooks.TrustedBinPrefixesEnv, "/opt/agents")
	account := selfWorkerAccount(t)
	response, err := runEnterpriseHookWorker(context.Background(), account, enterpriseHookWorkerRequest{
		Operation:  enterpriseHookWorkerOpApply,
		Standalone: true,
		Targets: []enterpriseHookWorkerTarget{
			workerTarget(account, 3, enterpriseHookWorkerModeInstall, "codex", false),
			workerTarget(account, 7, enterpriseHookWorkerModeVerifyOrRepair, "claudecode", true),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Targets) != 2 {
		t.Fatalf("targets = %+v", response.Targets)
	}
	for i, want := range []int{3, 7} {
		got := response.Targets[i]
		if got.Index != want || !got.OK || got.Result == nil || got.Repaired {
			t.Fatalf("target %d = %+v", i, got)
		}
		if got.Result.AgentVersion != account.Home {
			t.Fatalf("worker HOME = %q, want the target home %q", got.Result.AgentVersion, account.Home)
		}
		if got.Result.DataDir != "" {
			t.Fatalf("the guardian's environment leaked into the worker: %q", got.Result.DataDir)
		}
		if got.Result.HookContractID != "/opt/agents" {
			t.Fatalf("administrator passthrough env = %q", got.Result.HookContractID)
		}
	}
}

func TestEnterpriseHookWorkerRepairsDriftOnlyForProtectedTargets(t *testing.T) {
	useEnterpriseHookWorkerHelper(t, "drift")
	account := selfWorkerAccount(t)
	response, err := runEnterpriseHookWorker(context.Background(), account, enterpriseHookWorkerRequest{
		Operation: enterpriseHookWorkerOpApply,
		Targets: []enterpriseHookWorkerTarget{
			workerTarget(account, 0, enterpriseHookWorkerModeVerifyOrRepair, "codex", true),
			workerTarget(account, 1, enterpriseHookWorkerModeVerify, "codex", true),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := response.Targets[0]; !got.OK || !got.Repaired {
		t.Fatalf("drift on a protected target must be repaired: %+v", got)
	}
	if got := response.Targets[1]; got.OK || !strings.Contains(got.Error, "drifted") || got.Pending {
		t.Fatalf("verify must report drift without repairing: %+v", got)
	}
}

func TestEnterpriseHookWorkerReportsPerTargetFailures(t *testing.T) {
	useEnterpriseHookWorkerHelper(t, "fail")
	account := selfWorkerAccount(t)
	response, err := runEnterpriseHookWorker(context.Background(), account, enterpriseHookWorkerRequest{
		Operation: enterpriseHookWorkerOpApply,
		Targets:   []enterpriseHookWorkerTarget{workerTarget(account, 0, enterpriseHookWorkerModeInstall, "codex", false)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := response.Targets[0]; got.OK || got.Pending || got.Error != "install refused" {
		t.Fatalf("a failure inside an available home is a failure, not pending: %+v", got)
	}
}

func TestEnterpriseHookWorkerDiscoverRunsAsTheUser(t *testing.T) {
	useEnterpriseHookWorkerHelper(t, "ok")
	account := selfWorkerAccount(t)
	response, err := runEnterpriseHookWorker(context.Background(), account, enterpriseHookWorkerRequest{
		Operation:  enterpriseHookWorkerOpDiscover,
		Connectors: []string{"codex", "claudecode"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Versions["codex"] != "0.142.0" || response.Reasons["claudecode"] == "" {
		t.Fatalf("discover response = %+v", response)
	}
}

func TestEnterpriseHookWorkerRejectsMalformedOrRunawayWorkers(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want string
	}{
		{"garbage", "invalid JSON"},
		{"oversize", "oversized response"},
		{"sleep", "timed out"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			useEnterpriseHookWorkerHelper(t, tc.mode)
			origTimeout := enterpriseHookWorkerTimeout
			enterpriseHookWorkerTimeout = time.Second
			t.Cleanup(func() { enterpriseHookWorkerTimeout = origTimeout })
			account := selfWorkerAccount(t)
			started := time.Now()
			_, err := runEnterpriseHookWorker(context.Background(), account, enterpriseHookWorkerRequest{Operation: enterpriseHookWorkerOpApply})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if time.Since(started) > 10*time.Second {
				t.Fatalf("a runaway worker was not killed promptly (%s)", time.Since(started))
			}
		})
	}
}

func TestEnterpriseHookWorkerRefusesForeignOrRootIdentity(t *testing.T) {
	if _, err := runEnterpriseHookWorker(context.Background(), enterpriseHookWorkerAccount{UID: 0, GID: 0, Home: "/root"}, enterpriseHookWorkerRequest{}); err == nil {
		t.Fatal("a worker for uid 0 must be refused")
	}
	if os.Geteuid() != 0 {
		_, err := runEnterpriseHookWorker(context.Background(), enterpriseHookWorkerAccount{UID: os.Getuid() + 1, GID: os.Getgid(), Home: "/home/other"}, enterpriseHookWorkerRequest{})
		if err == nil || !strings.Contains(err.Error(), "only run a worker for itself") {
			t.Fatalf("a non-root parent must not target another uid: %v", err)
		}
	}
	home := filepath.Clean(t.TempDir())
	for name, request := range map[string]enterpriseHookWorkerRequest{
		"wrong uid":     {Version: enterpriseHookWorkerProtocolVersion, UID: os.Getuid() + 1, GID: os.Getgid(), Home: home},
		"wrong version": {Version: 99, UID: os.Getuid(), GID: os.Getgid(), Home: home},
		"root home":     {Version: enterpriseHookWorkerProtocolVersion, UID: os.Getuid(), GID: os.Getgid(), Home: "/"},
		"foreign target": {Version: enterpriseHookWorkerProtocolVersion, UID: os.Getuid(), GID: os.Getgid(), Home: home,
			Targets: []enterpriseHookWorkerTarget{{Options: enterpriseHookWorkerOptions{UserHome: "/elsewhere", OwnerUID: os.Getuid(), OwnerGID: os.Getgid()}}}},
	} {
		t.Run(name, func(t *testing.T) {
			if os.Geteuid() == 0 {
				t.Skip("identity mismatches are exercised as an unprivileged user")
			}
			payload, _ := json.Marshal(request)
			var stdout bytes.Buffer
			if code := enterpriseHookWorkerMain(context.Background(), bytes.NewReader(payload), &stdout, io.Discard); code != 4 {
				t.Fatalf("exit = %d, want 4 (%s)", code, stdout.String())
			}
			var response enterpriseHookWorkerResponse
			if err := json.Unmarshal(stdout.Bytes(), &response); err != nil || response.Error == "" || len(response.Targets) != 0 {
				t.Fatalf("response = %s (%v)", stdout.String(), err)
			}
		})
	}
	var stdout bytes.Buffer
	if code := enterpriseHookWorkerMain(context.Background(), strings.NewReader(`{"version":1,"unknown":true}`), &stdout, io.Discard); code != 3 {
		t.Fatalf("an unknown request field must be rejected, exit = %d", code)
	}
}

func TestEnterpriseHookWorkerPoolBoundsParallelism(t *testing.T) {
	origRunner := enterpriseHookWorkerRunner
	t.Cleanup(func() { enterpriseHookWorkerRunner = origRunner })
	var active, peak int32
	enterpriseHookWorkerRunner = func(_ context.Context, account enterpriseHookWorkerAccount, _ enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		now := atomic.AddInt32(&active, 1)
		for {
			old := atomic.LoadInt32(&peak)
			if now <= old || atomic.CompareAndSwapInt32(&peak, old, now) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		atomic.AddInt32(&active, -1)
		return enterpriseHookWorkerResponse{Versions: map[string]string{"uid": fmt.Sprint(account.UID)}}, nil
	}
	jobs := map[int]*enterpriseHookWorkerJob{}
	for uid := 1000; uid < 1012; uid++ {
		jobs[uid] = &enterpriseHookWorkerJob{Account: enterpriseHookWorkerAccount{UID: uid}}
	}
	outcomes := runEnterpriseHookWorkerPool(context.Background(), sortedWorkerJobs(jobs), enterpriseHookWorkerParallelism)
	if peak > enterpriseHookWorkerParallelism || peak < 2 {
		t.Fatalf("peak parallelism = %d, want 2..%d", peak, enterpriseHookWorkerParallelism)
	}
	for i, outcome := range outcomes {
		if want := fmt.Sprint(1000 + i); outcome.Response.Versions["uid"] != want {
			t.Fatalf("outcome %d is for uid %s, want %s", i, outcome.Response.Versions["uid"], want)
		}
	}
}

func TestDispatchEnterpriseHookStandaloneJobsDistrustsWorkerAnswers(t *testing.T) {
	origRunner := enterpriseHookWorkerRunner
	t.Cleanup(func() { enterpriseHookWorkerRunner = origRunner })
	account := enterpriseHookWorkerAccount{UID: 1001, GID: 1001, User: "alice", Home: "/home/alice"}
	enterpriseHookWorkerRunner = func(context.Context, enterpriseHookWorkerAccount, enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		return enterpriseHookWorkerResponse{Targets: []enterpriseHookWorkerTargetResult{
			{Index: 0, OK: true, Result: &enterprisehooks.InstallResult{Connector: "codex", UserHome: "/home/alice"}},
			{Index: 1, OK: true, Result: &enterprisehooks.InstallResult{Connector: "codex", UserHome: "/home/bob"}},
			{Index: 2, OK: true, Result: &enterprisehooks.InstallResult{Connector: "cursor", UserHome: "/home/alice"}},
			{Index: 3, OK: true},
			{Index: 4, Pending: true, Result: &enterprisehooks.InstallResult{Connector: "codex", UserHome: "/home/alice"}},
			{Index: 5, OK: true, Result: &enterprisehooks.InstallResult{Connector: "codex", UserHome: "/home/alice"}},
			{Index: 5, OK: true, Result: &enterprisehooks.InstallResult{Connector: "codex", UserHome: "/home/alice"}},
			{Index: 7, OK: true, Result: &enterprisehooks.InstallResult{Connector: "codex", UserHome: "/home/alice", HookScripts: []string{strings.Repeat("x", enterpriseHookWorkerResultMaxBytes)}}},
			{Index: 8, Pending: true},
			{Index: 42, OK: true, Result: &enterprisehooks.InstallResult{Connector: "codex", UserHome: "/home/alice"}},
		}}, nil
	}
	request := enterpriseHookWorkerRequest{Operation: enterpriseHookWorkerOpApply}
	for index := 0; index <= 8; index++ {
		request.Targets = append(request.Targets, workerTarget(account, index, enterpriseHookWorkerModeVerify, "codex", true))
	}
	outcomes := dispatchEnterpriseHookStandaloneJobs(context.Background(), map[int]*enterpriseHookWorkerJob{account.UID: {Account: account, Request: request}})
	if !outcomes[0].ok {
		t.Fatalf("a well-formed answer must succeed: %+v", outcomes[0])
	}
	for _, index := range []int{1, 2, 3, 4, 5, 6, 7} {
		if outcomes[index].ok || outcomes[index].pending || outcomes[index].err == "" {
			t.Fatalf("target %d: a forged, missing or inconsistent answer must fail: %+v", index, outcomes[index])
		}
	}
	if !outcomes[8].pending {
		t.Fatalf("a canonical pending answer must stay pending: %+v", outcomes[8])
	}
	if _, ok := outcomes[42]; ok {
		t.Fatal("an answer for a target that was never requested must be ignored")
	}
}

// standaloneTestDir returns a directory whose ancestors the home trust
// checks accept (t.TempDir() is below /tmp or the macOS /var symlink).
func standaloneTestDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(wd, ".m4-standalone-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if check := enterprisehooks.CheckUnixTargetHome(resolved, os.Getuid()); check.State == enterprisehooks.HomeUntrusted {
		t.Skipf("test working directory is not a trusted home parent: %s", check.Reason)
	}
	return resolved
}

type standaloneTestResolver struct {
	accounts  map[string]unixidentity.Account
	transient map[string]bool
}

func (r standaloneTestResolver) LookupUser(name string) (unixidentity.Account, error) {
	if r.transient[name] {
		return unixidentity.Account{}, errors.New("sssd: backend offline")
	}
	if account, ok := r.accounts[name]; ok {
		return account, nil
	}
	return unixidentity.Account{}, unixidentity.ErrNotFound
}

func (r standaloneTestResolver) LookupUID(uid int) (unixidentity.Account, error) {
	for name, account := range r.accounts {
		if account.UID == uid {
			return r.LookupUser(name)
		}
	}
	return unixidentity.Account{}, unixidentity.ErrNotFound
}

func (standaloneTestResolver) LookupGroup(string) (unixidentity.Group, error) {
	return unixidentity.Group{}, unixidentity.ErrNotFound
}

func (standaloneTestResolver) LookupGroupID(int) (unixidentity.Group, error) {
	return unixidentity.Group{}, unixidentity.ErrNotFound
}

func (standaloneTestResolver) GroupIDs(account unixidentity.Account) ([]int, error) {
	return []int{account.GID}, nil
}

func (standaloneTestResolver) ListUsers() ([]unixidentity.Account, bool, error) {
	return nil, false, nil
}

type standaloneFixture struct {
	root, homes, dataDir, authDir, manifest string
	mu                                      sync.Mutex
	requests                                []enterpriseHookWorkerRequest
}

// newStandaloneFixture puts the CLI into the standalone Unix profile with
// the root-only trust checks stubbed so the reconcile logic can run as an
// unprivileged user.
func newStandaloneFixture(t *testing.T, resolver unixidentity.Resolver) *standaloneFixture {
	t.Helper()
	root := standaloneTestDir(t)
	f := &standaloneFixture{
		root:     root,
		homes:    filepath.Join(root, "home"),
		dataDir:  filepath.Join(root, "data"),
		authDir:  filepath.Join(root, "auth"),
		manifest: filepath.Join(root, "targets.yaml"),
	}
	for _, dir := range []string{f.homes, f.dataDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, f.authDir)
	origCfg, origManifest := cfg, enterpriseHookManifest
	origPreflight, origManifestTrust, origRuntime := enterpriseHooksMutationIdentityPreflight, enterpriseHookManifestFileTrustCheck, enterpriseHookStandaloneRuntimeCheck
	origOwner, origDirTrust, origFileTrust, origStateTrust := enterpriseHookAuthorizationOwnershipSetter, enterpriseHookAuthorizationDirTrustCheck, enterpriseHookAuthorizationFileTrustCheck, enterpriseHookGuardianStateFileTrustCheck
	origToken, origOTLP, origRunner, origLog := enterpriseHookScopedTokenMinter, enterpriseHookScopedOTLPTokenMinter, enterpriseHookWorkerRunner, enterpriseHookWorkerLog
	origCheckHome := enterpriseHookCheckHome
	t.Cleanup(func() {
		cfg, enterpriseHookManifest = origCfg, origManifest
		enterpriseHooksMutationIdentityPreflight, enterpriseHookManifestFileTrustCheck, enterpriseHookStandaloneRuntimeCheck = origPreflight, origManifestTrust, origRuntime
		enterpriseHookAuthorizationOwnershipSetter, enterpriseHookAuthorizationDirTrustCheck, enterpriseHookAuthorizationFileTrustCheck, enterpriseHookGuardianStateFileTrustCheck = origOwner, origDirTrust, origFileTrust, origStateTrust
		enterpriseHookScopedTokenMinter, enterpriseHookScopedOTLPTokenMinter, enterpriseHookWorkerRunner, enterpriseHookWorkerLog = origToken, origOTLP, origRunner, origLog
		enterpriseHookCheckHome = origCheckHome
		enterprisehooks.SetStandaloneUnix(false)
		enterprisehooks.SetStandaloneResolver(nil)
	})
	cfg = standaloneTestConfig(f.dataDir)
	enterpriseHookManifest = f.manifest
	noop := func() error { return nil }
	noopPath := func(string) error { return nil }
	enterpriseHooksMutationIdentityPreflight = noop
	enterpriseHookStandaloneRuntimeCheck = noop
	enterpriseHookManifestFileTrustCheck = noopPath
	enterpriseHookAuthorizationOwnershipSetter = noopPath
	enterpriseHookAuthorizationDirTrustCheck = noopPath
	enterpriseHookAuthorizationFileTrustCheck = noopPath
	enterpriseHookGuardianStateFileTrustCheck = noopPath
	enterpriseHookScopedTokenMinter = func(string, string) (string, error) { return "scoped-token", nil }
	enterpriseHookScopedOTLPTokenMinter = func(string, string) (string, error) { return "otlp-token", nil }
	enterpriseHookWorkerLog = io.Discard
	enterprisehooks.SetStandaloneUnix(true)
	enterprisehooks.SetStandaloneResolver(resolver)
	enterpriseHookWorkerRunner = func(_ context.Context, account enterpriseHookWorkerAccount, request enterpriseHookWorkerRequest) (enterpriseHookWorkerResponse, error) {
		f.mu.Lock()
		f.requests = append(f.requests, request)
		f.mu.Unlock()
		response := enterpriseHookWorkerResponse{Version: enterpriseHookWorkerProtocolVersion}
		for _, target := range request.Targets {
			response.Targets = append(response.Targets, enterpriseHookWorkerTargetResult{
				Index: target.Index,
				OK:    true,
				Result: &enterprisehooks.InstallResult{
					Connector:                  target.Options.ConnectorName,
					UserHome:                   target.Options.UserHome,
					HookContractLockUpdatedAt:  "2026-09-26T00:00:00Z",
					HookContractEntryUpdatedAt: "2026-09-26T00:00:01Z",
				},
			})
		}
		return response, nil
	}
	return f
}

func standaloneTestConfig(dataDir string) *config.Config {
	c := &config.Config{DataDir: dataDir, DeploymentMode: "managed_enterprise"}
	c.Enterprise.Profile = "standalone"
	c.Gateway.APIPort = 18970
	c.Guardrail.Port = 4000
	return c
}

func (f *standaloneFixture) home(t *testing.T, name string, mode os.FileMode) string {
	t.Helper()
	home := filepath.Join(f.homes, name)
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(home, mode); err != nil {
		t.Fatal(err)
	}
	return home
}

func (f *standaloneFixture) writeManifest(t *testing.T, targets ...enterprisehooks.ManifestTarget) {
	t.Helper()
	enabled := true
	for i := range targets {
		targets[i].Enabled = &enabled
	}
	data, err := enterprisehooks.MarshalUnixTargetsManifest(enterprisehooks.Manifest{Version: 1, Targets: targets})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(f.manifest, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *standaloneFixture) writeLedger(t *testing.T, protected ...enterpriseHookReconcileRow) {
	t.Helper()
	if err := os.MkdirAll(f.authDir, 0o750); err != nil {
		t.Fatal(err)
	}
	ledger := enterpriseHookGuardianAuthorization{
		Version: 1, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano), OK: true,
		TargetCount: len(protected), SuccessCount: len(protected), ProtectedTargets: protected,
	}
	data, _ := json.MarshalIndent(ledger, "", "  ")
	if err := os.WriteFile(filepath.Join(f.authDir, hookGuardianAuthorizationFile), data, 0o640); err != nil {
		t.Fatal(err)
	}
}

func (f *standaloneFixture) writeBindings(t *testing.T, bindings map[string]enterpriseHookUnixBinding) {
	t.Helper()
	if err := os.MkdirAll(f.authDir, 0o750); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(enterpriseHookUnixBindings{Version: enterpriseHookUnixBindingsVersion, Bindings: bindings})
	if err := os.WriteFile(filepath.Join(f.authDir, enterpriseHookUnixBindingsFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (f *standaloneFixture) ledger(t *testing.T) enterpriseHookGuardianAuthorization {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(f.authDir, hookGuardianAuthorizationFile))
	if err != nil {
		t.Fatal(err)
	}
	var ledger enterpriseHookGuardianAuthorization
	if err := json.Unmarshal(data, &ledger); err != nil {
		t.Fatal(err)
	}
	return ledger
}

func (f *standaloneFixture) workerTargets() map[string]enterpriseHookWorkerTarget {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]enterpriseHookWorkerTarget{}
	for _, request := range f.requests {
		for _, target := range request.Targets {
			out[target.Options.ConnectorName+"@"+target.Options.UserHome] = target
		}
	}
	return out
}

func protectedRow(userName, home, connectorName string) enterpriseHookReconcileRow {
	return enterpriseHookReconcileRow{
		User: userName, UserHome: home, Connector: connectorName, OK: true,
		Result: &enterprisehooks.InstallResult{Connector: connectorName, UserHome: home},
	}
}

// requireLedgerOrStateTrust tolerates the one check an unprivileged test
// cannot stub: the service-runtime trust check on the state file.
func requireLedgerOrStateTrust(t *testing.T, err error) {
	t.Helper()
	if err != nil && (os.Geteuid() == 0 || !strings.Contains(err.Error(), "hook guardian state")) {
		t.Fatalf("state error = %v", err)
	}
}

func TestStandaloneReconcileSeparatesPendingFromTrustFailures(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	alice := f.home(t, "alice", 0o700)
	bob := filepath.Join(f.homes, "bob") // not created yet: pam_mkhomedir has not run
	carol := f.home(t, "carol", 0o770)
	for name, home := range map[string]string{"alice": alice, "bob": bob, "carol": carol} {
		resolver.accounts[name] = unixidentity.Account{Name: name, UID: uid, GID: gid, Home: home, Shell: "/bin/bash"}
	}
	f.writeManifest(t,
		enterprisehooks.ManifestTarget{User: "alice", Connector: "codex"},
		enterprisehooks.ManifestTarget{User: "alice", Connector: "claudecode"},
		enterprisehooks.ManifestTarget{User: "bob", Connector: "codex"},
		enterprisehooks.ManifestTarget{User: "carol", Connector: "codex"},
	)
	// bob was protected before his home went away.
	f.writeLedger(t, protectedRow("bob", bob, "codex"))
	bobKey := enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "bob", Connector: "codex"})
	f.writeBindings(t, map[string]enterpriseHookUnixBinding{bobKey: {UID: uid, Home: bob, LockUpdatedAt: "L", EntryUpdatedAt: "E"}})

	run, err := runEnterpriseHookReconcileOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireLedgerOrStateTrust(t, run.StateErr)
	if len(run.Rows) != 4 || run.Pending != 1 || run.Failures != 1 {
		t.Fatalf("rows = %+v pending=%d failures=%d", run.Rows, run.Pending, run.Failures)
	}
	if !run.Rows[0].OK || !run.Rows[1].OK {
		t.Fatalf("alice must be protected: %+v", run.Rows[:2])
	}
	if !run.Rows[2].Pending || run.Rows[2].Error != "" {
		t.Fatalf("a missing home is pending, not a failure: %+v", run.Rows[2])
	}
	if run.Rows[3].OK || !strings.Contains(run.Rows[3].Error, "group/other writable") {
		t.Fatalf("a group-writable home is a trust failure: %+v", run.Rows[3])
	}
	if got := len(f.requests); got != 1 {
		t.Fatalf("one worker per user expected, got %d requests", got)
	}
	ledger := f.ledger(t)
	if len(ledger.ProtectedTargets) != 2 || ledger.SuccessCount != 2 || ledger.PendingCount != 1 || ledger.FailureCount != 1 {
		t.Fatalf("a pending target must leave the ledger, keeping SuccessCount == len(protected): %+v", ledger)
	}
	for _, row := range ledger.ProtectedTargets {
		if row.User != "alice" {
			t.Fatalf("unexpected protected target %+v", row)
		}
		if row.UID != uid || row.HomeInode == 0 {
			t.Fatalf("a protected Unix target must carry its uid and home inode for peer authorization: %+v", row)
		}
	}
	bindings := loadEnterpriseHookUnixBindings()
	if len(bindings.Bindings) != 3 || bindings.Bindings[bobKey].LockUpdatedAt != "L" {
		t.Fatalf("bindings must record alice and keep bob's repair rights: %+v", bindings.Bindings)
	}
}

func TestStandaloneReconcileBindingsDetectUIDReuseAndKeepRepairRights(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	alice := f.home(t, "alice", 0o700)
	resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: uid, GID: gid, Home: alice}
	f.writeManifest(t,
		enterprisehooks.ManifestTarget{User: "alice", Connector: "codex"},
		enterprisehooks.ManifestTarget{User: "alice", Connector: "claudecode"},
	)
	codexKey := enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "alice", Connector: "codex"})
	claudeKey := enterpriseHookProtectedTargetKey(enterpriseHookReconcileRow{User: "alice", Connector: "claudecode"})
	// codex was protected for a previous owner of this name (uid reuse);
	// claudecode was protected before a pending cycle revoked its row.
	f.writeLedger(t, protectedRow("alice", alice, "codex"))
	f.writeBindings(t, map[string]enterpriseHookUnixBinding{
		codexKey:  {UID: uid + 1, Home: alice},
		claudeKey: {UID: uid, Home: alice, LockUpdatedAt: "lock-at", EntryUpdatedAt: "entry-at"},
	})
	run, err := runEnterpriseHookReconcileOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireLedgerOrStateTrust(t, run.StateErr)
	targets := f.workerTargets()
	codex := targets["codex@"+alice]
	if codex.PreviouslyProtected || codex.Options.AllowMissingHookConfigRepair {
		t.Fatalf("a reused uid must not inherit repair rights: %+v", codex)
	}
	claude := targets["claudecode@"+alice]
	if !claude.PreviouslyProtected || !claude.Options.AllowMissingHookConfigRepair ||
		claude.Options.RecoveryHookContractLockUpdatedAt != "lock-at" || claude.Options.RecoveryHookContractEntryUpdatedAt != "entry-at" {
		t.Fatalf("a matching binding must keep repair rights: %+v", claude)
	}
	bindings := loadEnterpriseHookUnixBindings()
	if bindings.Bindings[codexKey].UID != uid || bindings.Bindings[codexKey].HomeInode == 0 {
		t.Fatalf("a successful install must rebind to the current account: %+v", bindings.Bindings[codexKey])
	}
}

func TestStandaloneReconcileHonorsManifestIdentityDuringDirectoryOutage(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}, transient: map[string]bool{"ldapuser": true, "other": true}}
	f := newStandaloneFixture(t, resolver)
	ldap := f.home(t, "ldapuser", 0o700)
	other := f.home(t, "other", 0o700)
	resolver.accounts["ldapuser"] = unixidentity.Account{Name: "ldapuser", UID: uid, GID: gid, Home: ldap}
	f.writeManifest(t,
		enterprisehooks.ManifestTarget{User: "ldapuser", UserHome: ldap, UID: &uid, GID: &gid, Connector: "codex"},
		enterprisehooks.ManifestTarget{User: "other", UserHome: other, Connector: "codex"},
		enterprisehooks.ManifestTarget{User: "deleted", Connector: "codex"},
	)
	run, err := runEnterpriseHookReconcileOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	requireLedgerOrStateTrust(t, run.StateErr)
	if !run.Rows[0].OK {
		t.Fatalf("an explicit manifest identity must be honored during an NSS outage: %+v", run.Rows[0])
	}
	if !run.Rows[1].Pending {
		t.Fatalf("an NSS outage without explicit identity is pending, never deleted: %+v", run.Rows[1])
	}
	if run.Rows[2].OK || run.Rows[2].Pending || !strings.Contains(run.Rows[2].Error, "does not exist") {
		t.Fatalf("a definitive not-found is a failure: %+v", run.Rows[2])
	}
}

func TestStandaloneReconcileTreatsHungHomeAsPending(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	nfs := f.home(t, "nfsuser", 0o700)
	resolver.accounts["nfsuser"] = unixidentity.Account{Name: "nfsuser", UID: uid, GID: gid, Home: nfs}
	f.writeManifest(t, enterprisehooks.ManifestTarget{User: "nfsuser", Connector: "codex"})
	enterpriseHookCheckHome = func(home string, _ int) enterprisehooks.HomeCheck {
		return enterprisehooks.HomeCheck{State: enterprisehooks.HomePending, Reason: "user home " + home + " did not respond"}
	}
	run, err := runEnterpriseHookReconcileOnce(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(run.Rows) != 1 || !run.Rows[0].Pending || len(f.requests) != 0 {
		t.Fatalf("a hung home must be pending without starting a worker: %+v (%d requests)", run.Rows, len(f.requests))
	}
}

func TestMergeProtectedTargetsDropsPendingOnlyForStandalone(t *testing.T) {
	origCfg := cfg
	t.Cleanup(func() { cfg = origCfg })
	previous := []enterpriseHookReconcileRow{protectedRow("bob", "/home/bob", "codex")}
	current := []enterpriseHookReconcileRow{{User: "bob", UserHome: "/home/bob", Connector: "codex", Pending: true}}

	cfg = standaloneTestConfig("/var/lib/defenseclaw")
	if merged := mergeProtectedEnterpriseHookTargets(previous, current); len(merged) != 0 {
		t.Fatalf("standalone must revoke a pending target: %+v", merged)
	}
	// Secure Client keeps its historical carry-over.
	cfg = &config.Config{DataDir: "/var/lib/defenseclaw", DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = managed.ProfileSecureClient
	if merged := mergeProtectedEnterpriseHookTargets(previous, current); len(merged) != 1 {
		t.Fatalf("secure_client carry-over changed: %+v", merged)
	}
}

func TestStandaloneReconcileLockSerializesReconciles(t *testing.T) {
	_ = newStandaloneFixture(t, standaloneTestResolver{})
	unlock, err := lockEnterpriseHookReconcile(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	origWait := enterpriseHookReconcileLockWait
	enterpriseHookReconcileLockWait = 200 * time.Millisecond
	t.Cleanup(func() { enterpriseHookReconcileLockWait = origWait })
	if _, err := lockEnterpriseHookReconcile(context.Background()); err == nil || !strings.Contains(err.Error(), "another reconcile holds") {
		t.Fatalf("a second reconcile must wait and then fail: %v", err)
	}
	unlock()
	second, err := lockEnterpriseHookReconcile(context.Background())
	if err != nil {
		t.Fatalf("the lock must be free after unlock: %v", err)
	}
	second()
}

func TestEnterpriseHookCheckWorkerCapabilities(t *testing.T) {
	full := "Name:\tdefenseclaw\nCapEff:\t000001ffffffffff\n"
	if err := enterpriseHookCheckWorkerCapabilities(full); err != nil {
		t.Fatalf("full root capabilities: %v", err)
	}
	for name, status := range map[string]string{
		"no setuid": "CapEff:\t0000000000000040\n",
		"no setgid": "CapEff:\t0000000000000080\n",
		"none":      "CapEff:\t0000000000000000\n",
		"missing":   "Name:\tx\n",
		"garbage":   "CapEff:\tzz\n",
	} {
		if err := enterpriseHookCheckWorkerCapabilities(status); err == nil {
			t.Fatalf("%s: capabilities must be refused", name)
		}
	}
}

func TestEnterpriseHookStandaloneMutationPreflightIsStandaloneOnly(t *testing.T) {
	origCfg := cfg
	t.Cleanup(func() { cfg = origCfg })
	cfg = &config.Config{DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = managed.ProfileSecureClient
	if err := enterpriseHookStandaloneMutationPreflight(); err != nil {
		t.Fatalf("secure_client must keep its preflight unchanged: %v", err)
	}
	cfg = standaloneTestConfig(t.TempDir())
	err := enterpriseHookStandaloneMutationPreflight()
	if os.Geteuid() != 0 && (err == nil || !strings.Contains(err.Error(), "must run as root")) {
		t.Fatalf("an unprivileged standalone guardian must be refused: %v", err)
	}
}

func TestEnterpriseHookSessionUIDsFrom(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"1000", "1001", "0", "abc", "01002"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got := fmt.Sprint(enterpriseHookSessionUIDsFrom(dir)); got != "[1000 1001]" {
		t.Fatalf("session uids = %s", got)
	}
	if got := enterpriseHookSessionUIDsFrom(filepath.Join(dir, "missing")); got != nil {
		t.Fatalf("missing dir = %v", got)
	}
}

func TestEnterpriseHookStandaloneConfigChangeExitsOnlyForValidConfig(t *testing.T) {
	origCfg, origValidator := cfg, enterpriseHookStandaloneConfigValidator
	t.Cleanup(func() { cfg, enterpriseHookStandaloneConfigValidator = origCfg, origValidator })
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("a: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg = standaloneTestConfig(t.TempDir())
	cfg.ConfigFilePath = path
	startup := enterpriseHookStandaloneConfigFingerprint()
	if startup == "" || enterpriseHookStandaloneConfigChanged(startup, io.Discard) {
		t.Fatal("an unchanged config must not restart the guardian")
	}
	if err := os.WriteFile(path, []byte("a: 2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	enterpriseHookStandaloneConfigValidator = func(string) error { return errors.New("typo") }
	if enterpriseHookStandaloneConfigChanged(startup, io.Discard) {
		t.Fatal("an invalid config must not stop repair")
	}
	enterpriseHookStandaloneConfigValidator = func(string) error { return nil }
	if !enterpriseHookStandaloneConfigChanged(startup, io.Discard) {
		t.Fatal("a valid config change must restart the guardian")
	}
	cfg.Enterprise.Profile = managed.ProfileSecureClient
	if enterpriseHookStandaloneConfigFingerprint() != "" || enterpriseHookStandaloneConfigChanged(startup, io.Discard) {
		t.Fatal("secure_client watchers never restart on config changes")
	}
}

func TestWriteGuardianStateStandaloneUsesAuthorizationDir(t *testing.T) {
	f := newStandaloneFixture(t, standaloneTestResolver{})
	writeGuardianStateOrLog(io.Discard, guardianstate.StateReady)
	path := filepath.Join(f.authDir, guardianstate.FileName)
	if got := guardianstate.ReadState(path); got != guardianstate.StateReady {
		t.Fatalf("state at %s = %q", path, got)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("state file mode = %v (%v), want 0640 for the gateway group", info.Mode(), err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(f.manifest), guardianstate.FileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("standalone must not write the state beside the manifest: %v", err)
	}
	if want := guardianstate.PathForPlatform(enterpriseHooksStandaloneUnixActive(), cfg.DataDir, managed.HookGuardianAuthorizationDir(cfg.DataDir)); want != path {
		t.Fatalf("gateway reader path %s differs from the writer path %s", want, path)
	}
}

func TestStandaloneVerifyAcceptsOnlyRecordedPendingTargets(t *testing.T) {
	uid, gid := os.Getuid(), os.Getgid()
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{}}
	f := newStandaloneFixture(t, resolver)
	alice := f.home(t, "alice", 0o700)
	bob := filepath.Join(f.homes, "bob")
	resolver.accounts["alice"] = unixidentity.Account{Name: "alice", UID: uid, GID: gid, Home: alice}
	resolver.accounts["bob"] = unixidentity.Account{Name: "bob", UID: uid, GID: gid, Home: bob}
	f.writeManifest(t,
		enterprisehooks.ManifestTarget{User: "alice", Connector: "codex"},
		enterprisehooks.ManifestTarget{User: "bob", Connector: "codex"},
	)
	_, sha, err := enterprisehooks.LoadManifestWithSHA256(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	publish := func(rows []enterpriseHookReconcileRow) {
		t.Helper()
		// Publish the records as an unmanaged writer: the final state
		// trust check needs a root- or service-owned file.
		standalone := cfg
		cfg = &config.Config{DataDir: f.dataDir}
		defer func() { cfg = standalone }()
		if err := writeEnterpriseHookGuardianState(f.dataDir, f.manifest, sha, rows, 0, true); err != nil {
			t.Fatal(err)
		}
	}
	origLoadToken, origLoadOTLP := enterpriseHookStandaloneTokenLoader, enterpriseHookStandaloneOTLPTokenLoader
	t.Cleanup(func() {
		enterpriseHookStandaloneTokenLoader, enterpriseHookStandaloneOTLPTokenLoader = origLoadToken, origLoadOTLP
	})
	enterpriseHookStandaloneTokenLoader = func(string, string) (string, error) { return "scoped-token", nil }
	enterpriseHookStandaloneOTLPTokenLoader = func(string, string) (string, error) { return "", nil }

	publish([]enterpriseHookReconcileRow{protectedRow("alice", alice, "codex"), {User: "bob", UserHome: bob, Connector: "codex", Pending: true}})
	run, err := runEnterpriseHookVerifyAttempt(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if run.AuthorizationErr != nil || run.Failures != 0 || run.Pending != 1 || !run.Rows[0].OK || !run.Rows[1].Pending {
		t.Fatalf("recorded pending target: rows=%+v failures=%d pending=%d auth=%v", run.Rows, run.Failures, run.Pending, run.AuthorizationErr)
	}

	// The guardian never recorded bob pending: an unavailable home now is
	// a failure, not a free pass.
	publish([]enterpriseHookReconcileRow{protectedRow("alice", alice, "codex"), protectedRow("bob", bob, "codex")})
	run, err = runEnterpriseHookVerifyAttempt(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if run.Failures != 1 || run.Rows[1].OK || !strings.Contains(run.Rows[1].Error, "has not recorded it pending") {
		t.Fatalf("unrecorded pending target: rows=%+v failures=%d", run.Rows, run.Failures)
	}
}

func TestResolveEnterpriseHookTargetFallsBackToTheDirectory(t *testing.T) {
	resolver := standaloneTestResolver{accounts: map[string]unixidentity.Account{
		"ldap-only-user": {Name: "ldap-only-user", UID: 1234567, GID: 1234567, Home: "/home/ldap-only-user"},
	}}
	_ = newStandaloneFixture(t, resolver)
	target, err := resolveEnterpriseHookTargetValues("ldap-only-user", "", -1, -1, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if target.uid != 1234567 || target.gid != 1234567 || target.home != "/home/ldap-only-user" {
		t.Fatalf("target = %+v", target)
	}
	cfg.Enterprise.Profile = managed.ProfileSecureClient
	if _, err := resolveEnterpriseHookTargetValues("ldap-only-user", "", -1, -1, "", ""); err == nil {
		t.Fatal("secure_client must keep resolving through os/user only")
	}
}

// TestStandaloneWorkerSymlinkSwapCannotReachRootFiles is the root-only
// sentinel test: a target user plants a symlink from their agent config
// directory to a root-owned directory, and the real installer runs in the
// credential-dropped worker. Whatever the installer does, the root-owned
// sentinel must be untouched and nothing root-owned may appear in the
// user's home.
func TestStandaloneWorkerSymlinkSwapCannotReachRootFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-only: needs a real credential drop to an unprivileged uid")
	}
	const victimUID, victimGID = 54321, 54321
	base, err := os.MkdirTemp("/", ".defenseclaw-m4-sentinel-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	if err := os.Chmod(base, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinelDir := filepath.Join(base, "root-owned")
	if err := os.Mkdir(sentinelDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(sentinelDir, "config.toml")
	if err := os.WriteFile(sentinel, []byte("SENTINEL\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(base, "home", "victim")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Dir(home), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(home, victimUID, victimGID); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, ".codex")
	if err := os.Symlink(sentinelDir, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(link, victimUID, victimGID); err != nil {
		t.Fatal(err)
	}
	// The worker binary must be executable by the target uid.
	binDir := filepath.Join(base, "bin")
	if err := os.Mkdir(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	image, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	worker := filepath.Join(binDir, "worker")
	if err := os.WriteFile(worker, image, 0o755); err != nil {
		t.Fatal(err)
	}

	origExe, origArgs, origEnv, origLog := enterpriseHookWorkerExecutable, enterpriseHookWorkerArgs, enterpriseHookWorkerExtraEnv, enterpriseHookWorkerLog
	t.Cleanup(func() {
		enterpriseHookWorkerExecutable, enterpriseHookWorkerArgs, enterpriseHookWorkerExtraEnv, enterpriseHookWorkerLog = origExe, origArgs, origEnv, origLog
	})
	enterpriseHookWorkerExecutable = func() (string, error) { return worker, nil }
	enterpriseHookWorkerArgs = []string{"-test.run=^TestEnterpriseHookWorkerHelperProcess$"}
	enterpriseHookWorkerExtraEnv = []string{enterpriseHookWorkerHelperEnv + "=real"}
	var logs bytes.Buffer
	enterpriseHookWorkerLog = &logs

	account := enterpriseHookWorkerAccount{UID: victimUID, GID: victimGID, User: "victim", Home: home}
	target := workerTarget(account, 0, enterpriseHookWorkerModeInstall, "codex", true)
	target.Options.APIAddr = "127.0.0.1:18970"
	target.Options.DataDir = filepath.Join(home, ".defenseclaw")
	target.Options.AgentVersion = "0.142.0"
	target.Options.AllowMissingHookConfigRepair = true
	response, err := runEnterpriseHookWorker(context.Background(), account, enterpriseHookWorkerRequest{
		Operation: enterpriseHookWorkerOpApply, Standalone: true, Targets: []enterpriseHookWorkerTarget{target},
	})
	if err != nil {
		t.Fatalf("worker did not run as uid %d: %v\n%s", victimUID, err, logs.String())
	}
	t.Logf("installer outcome through the swapped symlink: %+v", response.Targets)

	if data, err := os.ReadFile(sentinel); err != nil || string(data) != "SENTINEL\n" {
		t.Fatalf("root-owned sentinel changed: %q (%v)", data, err)
	}
	entries, err := os.ReadDir(sentinelDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("the worker created files in a root-owned directory: %v (%v)", entries, err)
	}
	err = filepath.Walk(home, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && (st.Uid != victimUID) {
			return fmt.Errorf("%s is owned by uid %d, not the target user", path, st.Uid)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
