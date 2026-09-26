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
	opts := UnixEnumerateOptions{ExistingManifestPath: manifestPath, Resolver: resolver, HomeRoots: []string{homes}, UIDMin: uid, UIDMax: uid + 1, State: state}
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
