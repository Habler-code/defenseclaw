// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWindowsTargetUnselectedProofAcceptsAbsentRootAndRejectsSelection pins
// the #894 proof split. A target discovered after install whose user never
// signed in has no installer-created <home>\.defenseclaw root, so the
// deferred pending proof (which authorizes staging machine policy for it)
// rejects it; the unselected proof, which only establishes that DefenseClaw
// holds no managed runtime for the exact SID, accepts it. A selected runtime
// is still rejected.
func TestWindowsTargetUnselectedProofAcceptsAbsentRootAndRejectsSelection(t *testing.T) {
	fixture := newWindowsManagedRuntimeGenerationMissingHooksGCFixture(t)
	enabled := true

	rootless := ManifestTarget{
		UserHome:     newWindowsTargetOwnedTestHome(t, fixture.target),
		SID:          fixture.target.String(),
		Connector:    "codex",
		AgentVersion: "0.130.0",
		Enabled:      &enabled,
		Deferred:     true,
	}
	if _, err := os.Lstat(filepath.Join(rootless.UserHome, ".defenseclaw")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("rootless fixture unexpectedly has a data root: %v", err)
	}
	err := RequireWindowsEnterpriseDeferredTargetPending(rootless)
	if err == nil || !strings.Contains(err.Error(), "deferred target data directory is untrusted") {
		t.Fatalf("pending proof for an absent root = %v, want the untrusted data directory refusal", err)
	}
	if err := RequireWindowsEnterpriseTargetUnselected(rootless); err != nil {
		t.Fatalf("unselected proof rejected a rootless never-installed target: %v", err)
	}

	for _, tc := range []struct {
		name   string
		mutate func(*ManifestTarget)
	}{
		{"disabled", func(target *ManifestTarget) {
			disabled := false
			target.Enabled = &disabled
			target.Deferred = false
		}},
		{"unsupported_connector", func(target *ManifestTarget) { target.Connector = "openclaw" }},
		{"missing_home", func(target *ManifestTarget) {
			target.UserHome = filepath.Join(t.TempDir(), "absent")
		}},
	} {
		target := rootless
		tc.mutate(&target)
		if err := RequireWindowsEnterpriseTargetUnselected(target); err == nil {
			t.Errorf("%s: unselected proof accepted %+v", tc.name, target)
		}
	}

	selected := rootless
	selected.UserHome = filepath.Dir(fixture.options.DataDir)
	if err := RequireWindowsEnterpriseTargetUnselected(selected); err != nil {
		t.Fatalf("unselected proof before selection: %v", err)
	}
	selector := windowsManagedRuntimeSelector{
		SchemaVersion: windowsManagedRuntimeGenerationSchema,
		Connector:     fixture.options.Connector,
		Targets: []windowsManagedRuntimeSelectorTarget{{
			Connector:          fixture.options.Connector,
			SID:                fixture.options.TargetSID,
			DataDir:            fixture.options.DataDir,
			HookExecutable:     fixture.options.HookExecutable,
			GatewayAddr:        "127.0.0.1:18970",
			GatewayServiceName: "DefenseClawGateway",
			GenerationID:       strings.Repeat("a", 32),
			BundleSHA256:       "sha256:" + strings.Repeat("b", 64),
		}},
	}
	if err := publishWindowsManagedRuntimeSelector(selector); err != nil {
		t.Fatalf("publish selected target fixture: %v", err)
	}
	err = RequireWindowsEnterpriseTargetUnselected(selected)
	if err == nil || !strings.Contains(err.Error(), "already has a selected managed runtime") {
		t.Fatalf("unselected proof for a selected runtime = %v, want refusal", err)
	}
	// The selection is keyed by SID and connector, not by the data root.
	if err := RequireWindowsEnterpriseTargetUnselected(rootless); err == nil {
		t.Fatal("unselected proof accepted a selected SID because its home had no root")
	}
}

// TestWindowsDeferredPendingProofRequiresStageableClaudePolicy is the #894
// review regression for loadable legacy Claude Code rows. A deferred row at
// 2.1.152 or 2.1.153 (often an earlier installer's placeholder for a user with
// no detected client) has no hook contract, so deferred staging cannot render
// its machine policy. Reporting it pending made staging fail and roll back
// every other pending SID. It stays pending only when an earlier release
// already staged its SID, which staging skips.
func TestWindowsDeferredPendingProofRequiresStageableClaudePolicy(t *testing.T) {
	previous := windowsDeferredClaudePolicyTargetsReader
	t.Cleanup(func() { windowsDeferredClaudePolicyTargetsReader = previous })
	const (
		sid      = "S-1-5-21-1000-2000-3000-1105"
		otherSID = "S-1-5-21-1000-2000-3000-1101"
		refusal  = "deferred Claude Code machine policy cannot be staged"
	)
	enabled := true
	base := ManifestTarget{
		// A refused row never reaches the home checks; an accepted one fails
		// them on this absent home, which is not the staging refusal.
		UserHome:  filepath.Join(t.TempDir(), "absent"),
		SID:       sid,
		Connector: "claudecode",
		Enabled:   &enabled,
		Deferred:  true,
	}
	var staged []string
	var readErr error
	reads := 0
	windowsDeferredClaudePolicyTargetsReader = func() ([]string, bool, error) {
		reads++
		return staged, len(staged) > 0, readErr
	}
	for _, version := range []string{"2.1.152", "2.1.153"} {
		target := base
		target.AgentVersion = version

		staged, readErr = nil, nil
		err := RequireWindowsEnterpriseDeferredTargetPending(target)
		if err == nil || !strings.Contains(err.Error(), refusal) || !strings.Contains(err.Error(), version) {
			t.Fatalf("%s row with no staged policy: pending proof = %v, want the staging refusal", version, err)
		}

		staged = []string{otherSID}
		err = RequireWindowsEnterpriseDeferredTargetPending(target)
		if err == nil || !strings.Contains(err.Error(), refusal) {
			t.Fatalf("%s row when only another SID is staged: pending proof = %v, want the staging refusal", version, err)
		}

		// Staging compares SIDs case-insensitively; so does the proof.
		staged = []string{otherSID, strings.ToLower(sid)}
		err = RequireWindowsEnterpriseDeferredTargetPending(target)
		if err == nil || strings.Contains(err.Error(), refusal) {
			t.Fatalf("%s row already staged: pending proof = %v, want it to pass the staging check and fail later on the absent home", version, err)
		}

		staged, readErr = nil, errors.New("managed policy state unreadable")
		err = RequireWindowsEnterpriseDeferredTargetPending(target)
		if err == nil || !strings.Contains(err.Error(), refusal) || !strings.Contains(err.Error(), "managed policy state unreadable") {
			t.Fatalf("%s row with an unreadable policy: pending proof = %v, want the staging refusal and the read error", version, err)
		}
	}

	// A renderable version, and connectors whose staging does not render from
	// the recorded version, never consult the Claude Code policy.
	staged, readErr, reads = nil, nil, 0
	for _, target := range []ManifestTarget{
		func() ManifestTarget { target := base; target.AgentVersion = "2.1.154"; return target }(),
		func() ManifestTarget {
			target := base
			target.Connector = "cursor"
			target.AgentVersion = "1.7.0"
			return target
		}(),
		func() ManifestTarget {
			target := base
			target.Connector = "codex"
			target.AgentVersion = "0.144.3"
			return target
		}(),
	} {
		err := RequireWindowsEnterpriseDeferredTargetPending(target)
		if err == nil || strings.Contains(err.Error(), refusal) {
			t.Fatalf("%s %s: pending proof = %v, want the absent-home refusal only", target.Connector, target.AgentVersion, err)
		}
	}
	if reads != 0 {
		t.Fatalf("renderable rows read the Claude Code policy %d times, want 0", reads)
	}
}
