// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// Reconcile takes each target's watch paths from enterprisehooks.
// ResolveWatchPaths, which a root guardian on Unix runs in the per-target
// worker, and keeps each half only when it resolved.
func TestReconcileTakesWatchPathsFromResolveWatchPaths(t *testing.T) {
	stubSignInIsolationReconcile(t)
	previous := enterpriseHookReconcileWatchPaths
	t.Cleanup(func() { enterpriseHookReconcileWatchPaths = previous })
	var resolved []string
	enterpriseHookReconcileWatchPaths = func(_ context.Context, opts enterprisehooks.InstallOptions) enterprisehooks.WatchPathSet {
		resolved = append(resolved, opts.UserHome)
		set := enterprisehooks.WatchPathSet{
			Dirs: []string{filepath.Join(opts.UserHome, ".codex")},
			Ownership: enterprisehooks.WatchOwnership{
				ExclusiveWriter: []string{filepath.Join(opts.UserHome, ".defenseclaw", "hooks", "codex-hook.sh")},
				SharedWriter:    []string{filepath.Join(opts.UserHome, ".codex", "config.toml")},
			},
		}
		if filepath.Base(opts.UserHome) == "bob" {
			set.DirsErr = errors.New("enterprise hooks: data dir refused")
			set.OwnershipErr = errors.New("enterprise hooks: owned files refused")
		}
		return set
	}
	fixture, run := runSignInIsolationReconcile(t, []signInIsolationTarget{
		{name: "alice", sid: "S-1-5-21-1000-2000-3000-1101", connector: "codex"},
		{name: "bob", sid: "S-1-5-21-1000-2000-3000-1102", connector: "codex"},
	})
	alice, bob := fixture.homes["alice"], fixture.homes["bob"]
	if !slices.Equal(resolved, []string{alice, bob}) {
		t.Fatalf("watch paths resolved for %v, want alice then bob", resolved)
	}
	if !slices.Equal(run.WatchDirs, []string{filepath.Join(alice, ".codex")}) {
		t.Fatalf("watch dirs = %v, want only alice's resolved dir", run.WatchDirs)
	}
	if !slices.Equal(run.WatchExclusiveFiles, []string{filepath.Join(alice, ".defenseclaw", "hooks", "codex-hook.sh")}) ||
		!slices.Equal(run.WatchSharedFiles, []string{filepath.Join(alice, ".codex", "config.toml")}) {
		t.Fatalf("owned files = %v / %v, want only alice's", run.WatchExclusiveFiles, run.WatchSharedFiles)
	}
}
