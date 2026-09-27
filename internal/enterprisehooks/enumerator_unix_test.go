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

package enterprisehooks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// trustedTestDir returns a directory whose ancestors are not
// world-writable (t.TempDir() lives under /tmp on Linux and under the
// /var symlink on macOS, which the home checks rightly refuse).
func trustedTestDir(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(wd, ".m4-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if reason := worldWritableAncestor(filepath.Join(dir, "probe")); reason != "" {
		t.Skipf("test working directory has an unsuitable ancestor: %s", reason)
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
}

type fakeResolver struct {
	accounts   map[string]unixidentity.Account
	transient  map[string]bool
	groups     map[string][]int
	groupNames map[int]string
	listErr    error
	listed     []string
}

func (f *fakeResolver) LookupUser(name string) (unixidentity.Account, error) {
	if f.transient[name] {
		return unixidentity.Account{}, errors.New("directory unavailable")
	}
	if account, ok := f.accounts[name]; ok {
		return account, nil
	}
	return unixidentity.Account{}, unixidentity.ErrNotFound
}

func (f *fakeResolver) LookupUID(uid int) (unixidentity.Account, error) {
	for _, account := range f.accounts {
		if account.UID == uid {
			return f.LookupUser(account.Name)
		}
	}
	return unixidentity.Account{}, unixidentity.ErrNotFound
}

func (f *fakeResolver) LookupGroup(name string) (unixidentity.Group, error) {
	for gid, groupName := range f.groupNames {
		if groupName == name {
			return unixidentity.Group{Name: name, GID: gid}, nil
		}
	}
	return unixidentity.Group{}, unixidentity.ErrNotFound
}

func (f *fakeResolver) LookupGroupID(gid int) (unixidentity.Group, error) {
	if name, ok := f.groupNames[gid]; ok {
		return unixidentity.Group{Name: name, GID: gid}, nil
	}
	return unixidentity.Group{}, unixidentity.ErrNotFound
}

func (f *fakeResolver) GroupIDs(account unixidentity.Account) ([]int, error) {
	if f.transient["groups:"+account.Name] {
		return nil, errors.New("sssd timeout")
	}
	return append([]int{account.GID}, f.groups[account.Name]...), nil
}

func (f *fakeResolver) ListUsers() ([]unixidentity.Account, bool, error) {
	if f.listErr != nil {
		return nil, false, f.listErr
	}
	var out []unixidentity.Account
	for _, name := range f.listed {
		out = append(out, f.accounts[name])
	}
	return out, false, nil
}

func enumeratorConfig(connectors ...string) *config.Config {
	cfg := &config.Config{DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = "standalone"
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{}
	for _, name := range connectors {
		enabled := true
		cfg.Guardrail.Connectors[name] = config.PerConnectorGuardrailConfig{Enabled: &enabled}
	}
	return cfg
}

func makeHome(t *testing.T, root, name string) string {
	t.Helper()
	home := filepath.Join(root, name)
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	return home
}

func TestEnumerateUnixFiltersAndAutoEnrolls(t *testing.T) {
	root := trustedTestDir(t)
	homes := filepath.Join(root, "home")
	if err := os.MkdirAll(homes, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	alice := makeHome(t, homes, "alice")
	resolver := &fakeResolver{
		accounts: map[string]unixidentity.Account{
			"alice":   {Name: "alice", UID: uid, GID: gid, Home: alice, Shell: "/bin/bash"},
			"svc":     {Name: "svc", UID: uid, GID: gid, Home: alice, Shell: "/usr/sbin/nologin"},
			"lowuid":  {Name: "lowuid", UID: 5, GID: 5, Home: alice, Shell: "/bin/bash"},
			"outside": {Name: "outside", UID: uid, GID: gid, Home: filepath.Join(root, "elsewhere", "outside"), Shell: "/bin/bash"},
			"newbie":  {Name: "newbie", UID: uid, GID: gid, Home: filepath.Join(homes, "newbie"), Shell: "/bin/zsh"},
		},
		listed: []string{"alice", "svc", "lowuid", "outside", "newbie"},
	}
	discovered := map[string]map[string]string{}
	opts := UnixEnumerateOptions{
		Resolver:  resolver,
		HomeRoots: []string{homes},
		UIDMin:    uid, UIDMax: uid + 1,
		Discover: func(_ context.Context, account unixidentity.Account, connectors []string) (map[string]string, map[string]string, error) {
			discovered[account.Name] = map[string]string{}
			versions := map[string]string{}
			for _, conn := range connectors {
				discovered[account.Name][conn] = "asked"
				if conn == "codex" {
					versions[conn] = "0.150.0"
				}
			}
			return versions, map[string]string{"claudecode": "not installed"}, nil
		},
		MachineVersion: func(conn string) string {
			if conn == "claudecode" {
				return "2.1.300"
			}
			return ""
		},
	}
	cfg := enumeratorConfig("codex", "claudecode")
	manifest, report, err := EnumerateUnix(context.Background(), cfg, connector.NewDefaultRegistry(), opts)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, target := range manifest.Targets {
		got = append(got, target.User+"/"+target.Connector+"/"+target.AgentVersion)
		if target.User == "alice" && (target.HomeInode == 0 || target.Deferred) {
			t.Fatalf("alice row must bind the home inode and not be deferred: %+v", target)
		}
		if target.User == "newbie" && !target.Deferred {
			t.Fatalf("a user whose home does not exist yet must be deferred: %+v", target)
		}
	}
	want := []string{"alice/codex/0.150.0", "newbie/claudecode/2.1.300"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("rows = %v, want %v (skipped: %v)", got, want, report.Skipped)
	}
	if _, asked := discovered["newbie"]; asked {
		t.Fatal("discovery must not run for a user whose home is unavailable")
	}
	if len(report.EligibleAccounts) != 1 || report.EligibleAccounts[0].User != "alice" ||
		report.EligibleAccounts[0].Home != alice || report.EligibleAccounts[0].HomeInode == 0 {
		t.Fatalf("eligible accounts must list available homes only: %+v", report.EligibleAccounts)
	}
	for _, needle := range []string{"svc: non-interactive login shell", "lowuid: uid 5 outside", "outside: home"} {
		found := false
		for _, skipped := range report.Skipped {
			if strings.HasPrefix(skipped, needle) {
				found = true
			}
		}
		if !found {
			t.Errorf("expected a skip reason starting %q in %v", needle, report.Skipped)
		}
	}
}

func TestEnumerateUnixRefusesWorldWritableAncestorHomes(t *testing.T) {
	root := trustedTestDir(t)
	open := filepath.Join(root, "open")
	if err := os.MkdirAll(open, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o1777); err != nil {
		t.Fatal(err)
	}
	home := makeHome(t, open, "victim")
	check := CheckUnixTargetHome(home, os.Getuid())
	if check.State != HomeUntrusted || !strings.Contains(check.Reason, "world-writable") {
		t.Fatalf("home under a world-writable parent must be untrusted, got %+v", check)
	}
	if err := os.Chmod(home, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(open, 0o755); err != nil {
		t.Fatal(err)
	}
	if check := CheckUnixTargetHome(home, os.Getuid()); check.State != HomeUntrusted {
		t.Fatalf("group-writable home must be untrusted, got %+v", check)
	}
	if check := CheckUnixTargetHome(filepath.Join(open, "missing"), os.Getuid()); check.State != HomePending {
		t.Fatalf("missing home must be pending, got %+v", check)
	}
	link := filepath.Join(open, "linked")
	if err := os.Symlink(home, link); err != nil {
		t.Fatal(err)
	}
	if check := CheckUnixTargetHome(link, os.Getuid()); check.State != HomeUntrusted {
		t.Fatalf("symlinked home must be untrusted, got %+v", check)
	}
}

func TestEnumerateUnixPreservesKnownRowsThroughDirectoryFailures(t *testing.T) {
	root := trustedTestDir(t)
	homes := filepath.Join(root, "home")
	if err := os.MkdirAll(homes, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	ldap := makeHome(t, homes, "ldapuser")
	info, _ := os.Stat(ldap)
	inode := statInode(t, info)
	enabled := true
	manifestPath := filepath.Join(root, "targets.yaml")
	previous := Manifest{Version: 1, Targets: []ManifestTarget{
		{User: "ldapuser", UserHome: ldap, UID: intPointer(uid), GID: intPointer(gid), Connector: "codex", DataDir: filepath.Join(ldap, ".defenseclaw"), AgentVersion: "0.140.0", Enabled: &enabled, HomeInode: inode},
		{User: "gone", UserHome: filepath.Join(homes, "gone"), UID: intPointer(uid), GID: intPointer(gid), Connector: "codex", AgentVersion: "0.140.0", Enabled: &enabled},
	}}
	data, err := MarshalUnixTargetsManifest(previous)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	resolver := &fakeResolver{
		accounts:  map[string]unixidentity.Account{"ldapuser": {Name: "ldapuser", UID: uid, GID: gid, Home: ldap, Shell: "/bin/bash"}},
		transient: map[string]bool{"ldapuser": true},
		listErr:   errors.New("enumeration disabled"),
	}
	state := &UnixEnumeratorState{Version: 1, Misses: map[string]int{}}
	// No directory backend is configured, so "no such user" is definitive.
	opts := UnixEnumerateOptions{ExistingManifestPath: manifestPath, Resolver: resolver, HomeRoots: []string{homes}, UIDMin: uid, UIDMax: uid + 1, State: state,
		DirectoryConfigured: func() bool { return false }}
	cfg := enumeratorConfig("codex")
	for cycle := 1; cycle <= UnixRevokeAfterMisses; cycle++ {
		manifest, _, err := EnumerateUnix(context.Background(), cfg, connector.NewDefaultRegistry(), opts)
		if err != nil {
			t.Fatal(err)
		}
		users := map[string]bool{}
		for _, target := range manifest.Targets {
			users[target.User] = true
		}
		if !users["ldapuser"] {
			t.Fatalf("cycle %d: a transient directory error revoked ldapuser", cycle)
		}
		if wantGone := cycle < UnixRevokeAfterMisses; users["gone"] != wantGone {
			t.Fatalf("cycle %d: gone present=%v, want %v (misses=%v)", cycle, users["gone"], wantGone, state.Misses)
		}
	}
}

func TestEnumerateUnixKeepsEnrolledUserWhoLoosensTheirHome(t *testing.T) {
	root := trustedTestDir(t)
	homes := filepath.Join(root, "home")
	if err := os.MkdirAll(homes, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	enrolled := makeHome(t, homes, "enrolled")
	fresh := makeHome(t, homes, "fresh")
	for _, home := range []string{enrolled, fresh} {
		if err := os.Chmod(home, 0o770); err != nil {
			t.Fatal(err)
		}
	}
	enabled := true
	manifestPath := filepath.Join(root, "targets.yaml")
	previous := Manifest{Version: 1, Targets: []ManifestTarget{{
		User: "enrolled", UserHome: enrolled, UID: intPointer(uid), GID: intPointer(gid), Connector: "codex",
		AgentVersion: "0.140.0", Enabled: &enabled,
	}}}
	data, _ := MarshalUnixTargetsManifest(previous)
	if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	resolver := &fakeResolver{
		accounts: map[string]unixidentity.Account{
			"enrolled": {Name: "enrolled", UID: uid, GID: gid, Home: enrolled, Shell: "/bin/bash"},
			"fresh":    {Name: "fresh", UID: uid, GID: gid, Home: fresh, Shell: "/bin/bash"},
		},
		listed: []string{"enrolled", "fresh"},
	}
	opts := UnixEnumerateOptions{
		ExistingManifestPath: manifestPath, Resolver: resolver, HomeRoots: []string{homes}, UIDMin: uid, UIDMax: uid + 1,
		Discover: func(context.Context, unixidentity.Account, []string) (map[string]string, map[string]string, error) {
			return map[string]string{"codex": "0.150.0"}, nil, nil
		},
	}
	manifest, report, err := EnumerateUnix(context.Background(), enumeratorConfig("codex"), connector.NewDefaultRegistry(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Targets) != 1 || manifest.Targets[0].User != "enrolled" || manifest.Targets[0].AgentVersion != "0.140.0" {
		t.Fatalf("a group-writable home must keep an existing enrollment unchanged and never create a new one: %+v", manifest.Targets)
	}
	if report.Revoked != 0 || report.New != 0 {
		t.Fatalf("report = %+v", report)
	}
}

func TestEnumerateUnixReenrollsReusedUID(t *testing.T) {
	root := trustedTestDir(t)
	homes := filepath.Join(root, "home")
	if err := os.MkdirAll(homes, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	home := makeHome(t, homes, "reused")
	enabled := true
	manifestPath := filepath.Join(root, "targets.yaml")
	previous := Manifest{Version: 1, Targets: []ManifestTarget{{
		User: "reused", UserHome: home, UID: intPointer(uid), GID: intPointer(gid), Connector: "codex",
		AgentVersion: "0.100.0", Enabled: &enabled, HomeInode: 1, // a different, older home
	}}}
	data, _ := MarshalUnixTargetsManifest(previous)
	if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	resolver := &fakeResolver{accounts: map[string]unixidentity.Account{"reused": {Name: "reused", UID: uid, GID: gid, Home: home, Shell: "/bin/bash"}}, listed: []string{"reused"}}
	var logs []string
	opts := UnixEnumerateOptions{
		ExistingManifestPath: manifestPath, Resolver: resolver, HomeRoots: []string{homes}, UIDMin: uid, UIDMax: uid + 1,
		Discover: func(context.Context, unixidentity.Account, []string) (map[string]string, map[string]string, error) {
			return map[string]string{"codex": "0.150.0"}, nil, nil
		},
		Logger: func(subject, reason string) { logs = append(logs, reason) },
	}
	manifest, report, err := EnumerateUnix(context.Background(), enumeratorConfig("codex"), connector.NewDefaultRegistry(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Targets) != 1 || manifest.Targets[0].AgentVersion != "0.150.0" || manifest.Targets[0].HomeInode == 1 || report.New != 1 {
		t.Fatalf("a reused uid must be re-enrolled as new: %+v report=%+v", manifest.Targets, report)
	}
	if !strings.Contains(strings.Join(logs, "\n"), "re-enrolling as a new target") {
		t.Fatalf("uid reuse was not logged: %v", logs)
	}
}

func TestEnumerateUnixGroupFilters(t *testing.T) {
	root := trustedTestDir(t)
	homes := filepath.Join(root, "home")
	if err := os.MkdirAll(homes, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	for _, name := range []string{"dev", "contractor", "flaky"} {
		makeHome(t, homes, name)
	}
	resolver := &fakeResolver{
		accounts: map[string]unixidentity.Account{
			"dev":        {Name: "dev", UID: uid, GID: gid, Home: filepath.Join(homes, "dev"), Shell: "/bin/bash"},
			"contractor": {Name: "contractor", UID: uid, GID: gid, Home: filepath.Join(homes, "contractor"), Shell: "/bin/bash"},
			"flaky":      {Name: "flaky", UID: uid, GID: gid, Home: filepath.Join(homes, "flaky"), Shell: "/bin/bash"},
		},
		listed:     []string{"dev", "contractor", "flaky"},
		groups:     map[string][]int{"dev": {5001}, "contractor": {5001, 6000}},
		groupNames: map[int]string{5001: "ai-devs", 6000: "contractors"},
		transient:  map[string]bool{"groups:flaky": true},
	}
	cfg := enumeratorConfig("codex")
	cfg.Enterprise.Enrollment.IncludeGroups = []string{"ai-devs"}
	cfg.Enterprise.Enrollment.ExcludeGroups = []string{"contractors"}
	opts := UnixEnumerateOptions{Resolver: resolver, HomeRoots: []string{homes}, UIDMin: uid, UIDMax: uid + 1,
		Discover: func(context.Context, unixidentity.Account, []string) (map[string]string, map[string]string, error) {
			return map[string]string{"codex": "0.150.0"}, nil, nil
		}}
	manifest, _, err := EnumerateUnix(context.Background(), cfg, connector.NewDefaultRegistry(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Targets) != 1 || manifest.Targets[0].User != "dev" {
		t.Fatalf("group filters: rows = %+v", manifest.Targets)
	}
}

func TestEnumerateUnixMachinePolicyConnectorsNeedDenyForRows(t *testing.T) {
	cfg := enumeratorConfig("codex", "cursor")
	registry := connector.NewDefaultRegistry()
	resolver := &fakeResolver{}
	opts := UnixEnumerateOptions{Resolver: resolver, MachinePolicyConnectors: []string{"codex"}}
	_, report, err := EnumerateUnix(context.Background(), cfg, registry, opts)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(report.Connectors, ",") != "cursor" {
		t.Fatalf("machine-policy connectors must not get per-user rows by default: %v", report.Connectors)
	}
	cfg.Enterprise.Enrollment.UnenrolledUsers = config.EnterpriseUnenrolledDeny
	_, report, _ = EnumerateUnix(context.Background(), cfg, registry, opts)
	if strings.Join(report.Connectors, ",") != "codex,cursor" {
		t.Fatalf("unenrolled_users=deny needs rows for machine-policy connectors: %v", report.Connectors)
	}
}

func TestWriteUnixTargetsManifestAtomicIsByteStable(t *testing.T) {
	root := trustedTestDir(t)
	current := uint32(os.Getuid())
	previous := unixManifestTestOwnerAllowed
	unixManifestTestOwnerAllowed = func(uid uint32) bool { return uid == current }
	t.Cleanup(func() { unixManifestTestOwnerAllowed = previous })
	if err := validateRootOwnedDirChain(root); err != nil {
		// The publisher refuses any group-writable ancestor; a checkout
		// under one (e.g. a 0775 build tree) cannot host this test.
		t.Skipf("test directory chain cannot hold a manifest: %v", err)
	}
	path := filepath.Join(root, "targets.yaml")
	enabled := true
	manifest := Manifest{Version: 1, Targets: []ManifestTarget{{User: "a", UserHome: "/home/a", Connector: "codex", Enabled: &enabled, AgentVersion: "1.0.0"}}}
	changed, err := WriteUnixTargetsManifestAtomic(path, manifest)
	if err != nil || !changed {
		t.Fatalf("first write: changed=%v err=%v", changed, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("manifest mode = %o, want 0640", info.Mode().Perm())
	}
	changed, err = WriteUnixTargetsManifestAtomic(path, manifest)
	if err != nil || changed {
		t.Fatalf("identical write must be a no-op: changed=%v err=%v", changed, err)
	}
	loaded, err := LoadManifest(path)
	if err != nil || len(loaded.Targets) != 1 || loaded.Targets[0].User != "a" {
		t.Fatalf("round trip: %+v %v", loaded, err)
	}
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := WriteUnixTargetsManifestAtomic(path, manifest); err == nil {
		t.Fatal("a group/other-writable manifest directory was accepted")
	}
	_ = os.Chmod(root, 0o755)
}

func TestUnixEnumeratorStateRoundTrip(t *testing.T) {
	path := filepath.Join(trustedTestDir(t), "state.json")
	state := &UnixEnumeratorState{Misses: map[string]int{"alice\x00codex": 2}}
	if err := SaveUnixEnumeratorState(path, state); err != nil {
		t.Fatal(err)
	}
	loaded := LoadUnixEnumeratorState(path)
	if loaded.Misses["alice\x00codex"] != 2 {
		t.Fatalf("state round trip: %+v", loaded)
	}
	if err := os.WriteFile(path, []byte("{garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if fresh := LoadUnixEnumeratorState(path); len(fresh.Misses) != 0 {
		t.Fatalf("malformed state must start fresh: %+v", fresh)
	}
}

func withoutMachinePrefixes(t *testing.T) {
	t.Helper()
	previous := machinePrefixes
	machinePrefixes = func() []string { return nil }
	t.Cleanup(func() { machinePrefixes = previous })
}

func TestDiscoverUnixAgentVersionMetadataFirst(t *testing.T) {
	withoutMachinePrefixes(t)
	home := trustedTestDir(t)
	pkg := filepath.Join(home, ".npm-global", "lib", "node_modules", "@openai", "codex")
	if err := os.MkdirAll(pkg, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkg, "package.json"), []byte(`{"name":"@openai/codex","version":"0.151.2"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if version, _ := DiscoverUnixAgentVersion(context.Background(), home, "codex", false); version != "0.151.2" {
		t.Fatalf("codex version = %q", version)
	}
	amp := filepath.Join(home, ".npm-global", "lib", "node_modules", "@ampcode", "cli")
	if err := os.MkdirAll(amp, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(amp, "package.json"), []byte(`{"name":"not-amp","version":"9.9.9"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if version, _ := DiscoverUnixAgentVersion(context.Background(), home, "amp", false); version != "" {
		t.Fatalf("a package with the wrong name was trusted: %q", version)
	}
	versions := filepath.Join(home, ".local", "share", "claude", "versions")
	for _, v := range []string{"2.1.9", "2.1.219", "2.1.30", "not-a-version"} {
		if err := os.MkdirAll(filepath.Join(versions, v), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if version, _ := DiscoverUnixAgentVersion(context.Background(), home, "claudecode", false); version != "2.1.219" {
		t.Fatalf("claude version = %q, want the highest semver directory", version)
	}
	bad := filepath.Join(home, ".npm-global", "lib", "node_modules", "@github", "copilot")
	if err := os.MkdirAll(bad, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bad, "package.json"), []byte("{\"name\":\"@github/copilot\",\"version\":\"1.0.0\\nFAKE\"}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if version, _ := DiscoverUnixAgentVersion(context.Background(), home, "copilot", false); version != "" {
		t.Fatalf("a version with a control character was accepted: %q", version)
	}
}

func TestDiscoverUnixAgentVersionExecFallback(t *testing.T) {
	withoutMachinePrefixes(t)
	home := trustedTestDir(t)
	bin := filepath.Join(home, ".local", "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\nif [ -n \"$DEFENSECLAW_LEAK\" ]; then echo leaked; exit 0; fi\necho 'devin 3000.4.25 (build abc)'\n"
	if err := os.WriteFile(filepath.Join(bin, "devin"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DEFENSECLAW_LEAK", "1")
	if version, _ := DiscoverUnixAgentVersion(context.Background(), home, "devin", false); version != "" {
		t.Fatalf("exec fallback ran without allowExec: %q", version)
	}
	if version, _ := DiscoverUnixAgentVersion(context.Background(), home, "devin", true); version != "3000.4.25" {
		t.Fatalf("devin version = %q", version)
	}
	for line, want := range map[string]string{
		"codex-cli 0.142.0":     "0.142.0",
		"2.1.187 (Claude Code)": "2.1.187",
		"v1.2.3":                "1.2.3",
		"no version here":       "",
	} {
		if got := ExtractUnixAgentVersion(line); got != want {
			t.Errorf("ExtractUnixAgentVersion(%q) = %q, want %q", line, got, want)
		}
	}
}

func statInode(t *testing.T, info os.FileInfo) uint64 {
	t.Helper()
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("no stat_t")
	}
	return uint64(st.Ino)
}

// A manifest that does not load (here an administrator disabled a deferred
// row without clearing deferred) must fail the cycle. Rebuilding it from
// scratch re-enabled the disabled row and dropped every user who was not
// rediscovered this cycle, without the miss count.
func TestEnumerateUnixKeepsAnUnloadableManifest(t *testing.T) {
	root := trustedTestDir(t)
	homes := filepath.Join(root, "home")
	if err := os.MkdirAll(homes, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	alice := makeHome(t, homes, "alice")
	manifestPath := filepath.Join(root, "targets.yaml")
	raw := []byte("version: 1\ntargets:\n  - user: alice\n    user_home: " + alice + "\n    connector: codex\n    agent_version: 0.140.0\n    enabled: false\n    deferred: true\n")
	if err := os.WriteFile(manifestPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	resolver := &fakeResolver{
		accounts: map[string]unixidentity.Account{"alice": {Name: "alice", UID: uid, GID: gid, Home: alice, Shell: "/bin/bash"}},
		listed:   []string{"alice"},
	}
	opts := UnixEnumerateOptions{
		ExistingManifestPath: manifestPath, Resolver: resolver, HomeRoots: []string{homes}, UIDMin: uid, UIDMax: uid + 1,
		Discover: func(context.Context, unixidentity.Account, []string) (map[string]string, map[string]string, error) {
			return map[string]string{"codex": "0.150.0"}, nil, nil
		},
	}
	manifest, _, err := EnumerateUnix(context.Background(), enumeratorConfig("codex"), connector.NewDefaultRegistry(), opts)
	if err == nil || !strings.Contains(err.Error(), "does not load") {
		t.Fatalf("an unloadable manifest must fail the cycle, got err=%v manifest=%+v", err, manifest)
	}
	if len(manifest.Targets) != 0 {
		t.Fatalf("no manifest may be produced for publication: %+v", manifest.Targets)
	}
	after, readErr := os.ReadFile(manifestPath)
	if readErr != nil || string(after) != string(raw) {
		t.Fatalf("the administrator's manifest must be left unchanged: %v\n%s", readErr, after)
	}
	// A missing manifest is still a first run.
	if _, _, err := EnumerateUnix(context.Background(), enumeratorConfig("codex"), connector.NewDefaultRegistry(), UnixEnumerateOptions{
		ExistingManifestPath: filepath.Join(root, "absent.yaml"), Resolver: resolver, HomeRoots: []string{homes}, UIDMin: uid, UIDMax: uid + 1,
	}); err != nil {
		t.Fatalf("a missing manifest must not fail the cycle: %v", err)
	}
}

// A locked ecryptfs home shows its lower mountpoint directory, whose inode
// differs from the mounted root the user was enrolled under. Comparing the
// two re-enrolled the user as a new target (and revoked a per-user row) on
// every logout; a pending home's inode must be neither compared nor bound.
func TestEnumerateUnixPendingHomeKeepsTheEnrolledInode(t *testing.T) {
	SetStandaloneUnix(true) // deferred Unix rows load only in the standalone profile
	t.Cleanup(func() { SetStandaloneUnix(false) })
	root := trustedTestDir(t)
	homes := filepath.Join(root, "home")
	if err := os.MkdirAll(homes, 0o755); err != nil {
		t.Fatal(err)
	}
	uid, gid := os.Getuid(), os.Getgid()
	alice := filepath.Join(homes, "alice")
	bob := filepath.Join(homes, "bob")
	enabled := true
	manifestPath := filepath.Join(root, "targets.yaml")
	previous := Manifest{Version: 1, Targets: []ManifestTarget{{
		User: "alice", UserHome: alice, UID: intPointer(uid), GID: intPointer(gid), Connector: "opencode",
		DataDir: filepath.Join(alice, ".defenseclaw"), AgentVersion: "1.0.0", Enabled: &enabled, HomeInode: 555,
	}}}
	data, _ := MarshalUnixTargetsManifest(previous)
	if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	resolver := &fakeResolver{
		accounts: map[string]unixidentity.Account{
			"alice": {Name: "alice", UID: uid, GID: gid, Home: alice, Shell: "/bin/bash"},
			"bob":   {Name: "bob", UID: uid, GID: gid, Home: bob, Shell: "/bin/bash"},
		},
		listed: []string{"alice", "bob"},
	}
	state := map[string]HomeCheck{
		alice: {State: HomePending, Reason: "locked", Inode: 777},
		bob:   {State: HomePending, Reason: "locked", Inode: 888},
	}
	var logs []string
	opts := UnixEnumerateOptions{
		ExistingManifestPath: manifestPath, Resolver: resolver, HomeRoots: []string{homes}, UIDMin: uid, UIDMax: uid + 1,
		CheckHome:      func(home string, _ int) HomeCheck { return state[home] },
		MachineVersion: func(string) string { return "1.0.0" },
		Logger:         func(_, reason string) { logs = append(logs, reason) },
	}
	cfg := enumeratorConfig("opencode")
	manifest, report, err := EnumerateUnix(context.Background(), cfg, connector.NewDefaultRegistry(), opts)
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]ManifestTarget{}
	for _, target := range manifest.Targets {
		rows[target.User] = target
	}
	if got := rows["alice"]; !got.Deferred || got.HomeInode != 555 || got.AgentVersion != "1.0.0" || report.Revoked != 0 {
		t.Fatalf("a locked home must keep the enrolled row and inode: %+v report=%+v logs=%v", got, report, logs)
	}
	if got := rows["bob"]; !got.Deferred || got.HomeInode != 0 {
		t.Fatalf("a new deferred row must not bind a pending home's inode: %+v", got)
	}
	if strings.Contains(strings.Join(logs, "\n"), "re-enrolling") {
		t.Fatalf("a lock state change is not an identity change: %v", logs)
	}
	// Unlocked again: the mounted root has the enrolled inode.
	state[alice] = HomeCheck{State: HomeAvailable, Inode: 555}
	data, _ = MarshalUnixTargetsManifest(manifest)
	if err := os.WriteFile(manifestPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	manifest, report, err = EnumerateUnix(context.Background(), cfg, connector.NewDefaultRegistry(), opts)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range manifest.Targets {
		if target.User == "alice" && (target.Deferred || target.HomeInode != 555) {
			t.Fatalf("an unlocked home must resume the enrolled row: %+v", target)
		}
	}
	if report.New != 0 || report.Revoked != 0 {
		t.Fatalf("unlock must not re-enroll: %+v", report)
	}
}

func availableHome(string, int) HomeCheck { return HomeCheck{State: HomeAvailable, Inode: 42} }

func writeTestManifest(t *testing.T, path string, targets ...ManifestTarget) {
	t.Helper()
	enabled := true
	for i := range targets {
		targets[i].Enabled = &enabled
	}
	data, err := MarshalUnixTargetsManifest(Manifest{Version: 1, Targets: targets})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func manifestUsers(m Manifest) map[string]bool {
	users := map[string]bool{}
	for _, target := range m.Targets {
		users[target.User] = true
	}
	return users
}

// login.defs UID_MAX (60000 on RHEL and Ubuntu) excluded every SSSD
// id-mapped, FreeIPA and systemd-homed account. It now bounds only local
// accounts unless enterprise.enrollment.uid_max is set; systemd's dynamic
// service uids are never enrolled.
func TestEnumerateUnixDirectoryUIDsAreNotBoundByLoginDefs(t *testing.T) {
	root := trustedTestDir(t)
	homes := filepath.Join(root, "home")
	accounts := map[string]unixidentity.Account{}
	var listed []string
	for name, uid := range map[string]int{"adalice": 1234401103, "homed": 60100, "localhigh": 70000, "localuser": 1500, "dyn": 61200} {
		accounts[name] = unixidentity.Account{Name: name, UID: uid, GID: uid, Home: filepath.Join(homes, name), Shell: "/bin/bash"}
		listed = append(listed, name)
	}
	resolver := &fakeResolver{accounts: accounts, listed: listed}
	opts := UnixEnumerateOptions{
		Resolver: resolver, HomeRoots: []string{homes}, UIDMin: 1000, UIDMax: 60000, CheckHome: availableHome,
		LocalAccounts: func() (map[string]int, error) {
			return map[string]int{"root": 0, "localhigh": 70000, "localuser": 1500}, nil
		},
		Discover: func(context.Context, unixidentity.Account, []string) (map[string]string, map[string]string, error) {
			return map[string]string{"opencode": "1.0.0"}, nil, nil
		},
	}
	cfg := enumeratorConfig("opencode")
	manifest, report, err := EnumerateUnix(context.Background(), cfg, connector.NewDefaultRegistry(), opts)
	if err != nil {
		t.Fatal(err)
	}
	users := manifestUsers(manifest)
	want := map[string]bool{"adalice": true, "homed": true, "localuser": true}
	if runtime.GOOS != "linux" {
		want["dyn"] = true
	}
	if len(users) != len(want) {
		t.Fatalf("enrolled = %v, want %v (skipped %v)", users, want, report.Skipped)
	}
	for name := range want {
		if !users[name] {
			t.Fatalf("enrolled = %v, want %v (skipped %v)", users, want, report.Skipped)
		}
	}
	// An explicit uid_max applies to every account.
	cfg.Enterprise.Enrollment.UIDMax = 100000
	manifest, _, err = EnumerateUnix(context.Background(), cfg, connector.NewDefaultRegistry(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if users := manifestUsers(manifest); users["adalice"] || !users["localhigh"] || !users["homed"] {
		t.Fatalf("uid_max=100000 enrolled %v", users)
	}
	// Without the local account database every account keeps UID_MAX.
	cfg.Enterprise.Enrollment.UIDMax = 0
	opts.LocalAccounts = func() (map[string]int, error) { return nil, errors.New("unreadable") }
	manifest, _, err = EnumerateUnix(context.Background(), cfg, connector.NewDefaultRegistry(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if users := manifestUsers(manifest); users["adalice"] || !users["localuser"] {
		t.Fatalf("an unknown account source must keep UID_MAX: %v", users)
	}
}

// getent exits 2 for a deleted account and for every directory account
// while sssd, nslcd or ypbind cannot reach the directory. A directory
// user's "no such user" counts only when another directory account resolved
// in the same cycle; a local account's counts at once.
func TestEnumerateUnixDirectoryOutageNeverRevokes(t *testing.T) {
	root := trustedTestDir(t)
	homes := filepath.Join(root, "home")
	manifestPath := filepath.Join(root, "targets.yaml")
	uid := 1234401103
	writeTestManifest(t, manifestPath,
		ManifestTarget{User: "alice", UserHome: filepath.Join(homes, "alice"), UID: intPointer(uid), GID: intPointer(uid), Connector: "opencode", AgentVersion: "1.0.0", HomeInode: 42},
		ManifestTarget{User: "carol", UserHome: filepath.Join(homes, "carol"), UID: intPointer(1500), GID: intPointer(1500), Connector: "opencode", AgentVersion: "1.0.0", HomeInode: 42},
	)
	state := &UnixEnumeratorState{Version: 1, Misses: map[string]int{}, Sources: map[string]string{"alice": unixSourceDirectory, "carol": unixSourceFiles}}
	// The outage: only local accounts answer; alice and the deleted local
	// user carol both come back "not found" (exit 2).
	resolver := &fakeResolver{accounts: map[string]unixidentity.Account{
		"root": {Name: "root", UID: 0, GID: 0, Home: "/root", Shell: "/bin/bash"},
	}, listed: []string{"root"}}
	opts := UnixEnumerateOptions{
		ExistingManifestPath: manifestPath, Resolver: resolver, HomeRoots: []string{homes}, UIDMin: 1000, UIDMax: 60000,
		CheckHome: availableHome, State: state,
		LocalAccounts:       func() (map[string]int, error) { return map[string]int{"root": 0}, nil },
		DirectoryConfigured: func() bool { return true },
	}
	cfg := enumeratorConfig("opencode")
	for cycle := 1; cycle <= UnixRevokeAfterMisses+3; cycle++ {
		manifest, _, err := EnumerateUnix(context.Background(), cfg, connector.NewDefaultRegistry(), opts)
		if err != nil {
			t.Fatal(err)
		}
		users := manifestUsers(manifest)
		if !users["alice"] {
			t.Fatalf("cycle %d: a directory outage revoked alice (misses=%v)", cycle, state.Misses)
		}
		if wantCarol := cycle < UnixRevokeAfterMisses; users["carol"] != wantCarol {
			t.Fatalf("cycle %d: deleted local user present=%v, want %v", cycle, users["carol"], wantCarol)
		}
		writeTestManifest(t, manifestPath, manifest.Targets...)
	}
	// The directory answers again (bob resolves) but alice is really gone.
	resolver.accounts["bob"] = unixidentity.Account{Name: "bob", UID: 1234401200, GID: 1234401200, Home: filepath.Join(homes, "bob"), Shell: "/bin/bash"}
	resolver.listed = append(resolver.listed, "bob")
	for cycle := 1; cycle <= UnixRevokeAfterMisses; cycle++ {
		manifest, _, err := EnumerateUnix(context.Background(), cfg, connector.NewDefaultRegistry(), opts)
		if err != nil {
			t.Fatal(err)
		}
		if wantAlice := cycle < UnixRevokeAfterMisses; manifestUsers(manifest)["alice"] != wantAlice {
			t.Fatalf("directory up, cycle %d: alice present=%v, want %v", cycle, !wantAlice, wantAlice)
		}
		writeTestManifest(t, manifestPath, manifest.Targets...)
	}
	if _, ok := state.Sources["alice"]; ok {
		t.Fatalf("a revoked user's source must be forgotten: %v", state.Sources)
	}
}

// A missing include-group membership can be a partial answer from a
// degraded directory; it revoked an enrolled user in the same cycle.
func TestEnumerateUnixGroupFilterRevocationUsesMissCounting(t *testing.T) {
	root := trustedTestDir(t)
	homes := filepath.Join(root, "home")
	manifestPath := filepath.Join(root, "targets.yaml")
	resolver := &fakeResolver{
		accounts: map[string]unixidentity.Account{
			"dev":        {Name: "dev", UID: 2001, GID: 2001, Home: filepath.Join(homes, "dev"), Shell: "/bin/bash"},
			"contractor": {Name: "contractor", UID: 2002, GID: 2002, Home: filepath.Join(homes, "contractor"), Shell: "/bin/bash"},
		},
		listed:     []string{"dev", "contractor"},
		groups:     map[string][]int{"dev": {}, "contractor": {5001, 6000}},
		groupNames: map[int]string{5001: "ai-devs", 6000: "contractors"},
	}
	writeTestManifest(t, manifestPath,
		ManifestTarget{User: "dev", UserHome: filepath.Join(homes, "dev"), UID: intPointer(2001), GID: intPointer(2001), Connector: "opencode", AgentVersion: "1.0.0", HomeInode: 42},
		ManifestTarget{User: "contractor", UserHome: filepath.Join(homes, "contractor"), UID: intPointer(2002), GID: intPointer(2002), Connector: "opencode", AgentVersion: "1.0.0", HomeInode: 42},
	)
	cfg := enumeratorConfig("opencode")
	cfg.Enterprise.Enrollment.IncludeGroups = []string{"ai-devs"}
	cfg.Enterprise.Enrollment.ExcludeGroups = []string{"contractors"}
	state := &UnixEnumeratorState{Version: 1, Misses: map[string]int{}}
	opts := UnixEnumerateOptions{ExistingManifestPath: manifestPath, Resolver: resolver, HomeRoots: []string{homes}, UIDMin: 1000, UIDMax: 60000, CheckHome: availableHome, State: state}
	for cycle := 1; cycle <= UnixRevokeAfterMisses; cycle++ {
		manifest, _, err := EnumerateUnix(context.Background(), cfg, connector.NewDefaultRegistry(), opts)
		if err != nil {
			t.Fatal(err)
		}
		users := manifestUsers(manifest)
		if users["contractor"] {
			t.Fatalf("cycle %d: membership of an excluded group revokes at once", cycle)
		}
		if wantDev := cycle < UnixRevokeAfterMisses; users["dev"] != wantDev {
			t.Fatalf("cycle %d: dev present=%v, want %v (misses=%v)", cycle, users["dev"], wantDev, state.Misses)
		}
		writeTestManifest(t, manifestPath, manifest.Targets...)
	}
}

// The gateway matches exempt_users by kernel-verified uid, the enumerator
// only by name, so no single spelling worked for a directory user in both.
func TestEnumerateUnixExcludeAndExemptAcceptUIDs(t *testing.T) {
	root := trustedTestDir(t)
	homes := filepath.Join(root, "home")
	accounts := map[string]unixidentity.Account{}
	for name, uid := range map[string]int{"svc-release": 1500, "build": 1600, "alice": 1700} {
		accounts[name] = unixidentity.Account{Name: name, UID: uid, GID: uid, Home: filepath.Join(homes, name), Shell: "/bin/bash"}
	}
	resolver := &fakeResolver{accounts: accounts, listed: []string{"svc-release", "build", "alice"}}
	cfg := enumeratorConfig("opencode")
	cfg.Enterprise.Enrollment.ExemptUsers = []string{"1500"}
	cfg.Enterprise.Enrollment.ExcludeUsers = []string{"1600"}
	opts := UnixEnumerateOptions{
		Resolver: resolver, HomeRoots: []string{homes}, UIDMin: 1000, UIDMax: 60000, CheckHome: availableHome,
		Discover: func(context.Context, unixidentity.Account, []string) (map[string]string, map[string]string, error) {
			return map[string]string{"opencode": "1.0.0"}, nil, nil
		},
	}
	manifest, report, err := EnumerateUnix(context.Background(), cfg, connector.NewDefaultRegistry(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if users := manifestUsers(manifest); len(users) != 1 || !users["alice"] {
		t.Fatalf("enrolled = %v (skipped %v)", users, report.Skipped)
	}
	joined := strings.Join(report.Skipped, "\n")
	if !strings.Contains(joined, "svc-release: exempt") || !strings.Contains(joined, "build: excluded") {
		t.Fatalf("skipped = %v", report.Skipped)
	}
}
