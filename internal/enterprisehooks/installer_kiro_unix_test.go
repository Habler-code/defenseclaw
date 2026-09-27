//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func kiroStandaloneInstallOptions(home, version string) InstallOptions {
	return InstallOptions{
		ConnectorName: "kiro",
		UserHome:      home,
		OwnerUID:      os.Getuid(),
		OwnerGID:      os.Getgid(),
		APIAddr:       "127.0.0.1:18970",
		ProxyAddr:     "127.0.0.1:4000",
		APIToken:      "test-token",
		OTLPPathToken: strings.Repeat("d", 64),
		GuardrailMode: "action",
		HookFailMode:  "closed",
		AgentVersion:  version,
		Registry:      connector.NewDefaultRegistry(),
		// Protected before: repair may rewrite the existing hook config.
		AllowMissingHookConfigRepair: true,
	}
}

// Kiro's hook contract is not version-gated, so it never resolves to a known
// contract. The standalone guardian only followed an agent upgrade to a
// known contract, so every kiro-cli self-update left the user's row refusing
// its repair with "hook contract drift detected". It now follows an upgrade
// at or above the certified minimum and refuses anything below it.
func TestStandaloneKiroFollowsCLIUpgradesAtOrAboveTheFloor(t *testing.T) {
	skipIfRoot(t)
	t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "")
	setStandaloneProfileForTest(t, true)
	home := newTestHome(t)

	if _, err := Install(context.Background(), kiroStandaloneInstallOptions(home, "kiro-cli 2.24.1")); err != nil {
		t.Fatalf("first install at the certified version: %v", err)
	}
	hooks := filepath.Join(home, ".kiro", "hooks", "defenseclaw.json")
	if _, err := os.Stat(hooks); err != nil {
		t.Fatalf("global Kiro hook file missing: %v", err)
	}

	upgraded, err := Install(context.Background(), kiroStandaloneInstallOptions(home, "kiro-cli 2.25.0"))
	if err != nil {
		t.Fatalf("repair after a kiro-cli self-update: %v", err)
	}
	if upgraded.AgentVersion != "kiro-cli 2.25.0" {
		t.Fatalf("repair recorded %q, want the new version", upgraded.AgentVersion)
	}
	if _, err := Verify(context.Background(), kiroStandaloneInstallOptions(home, "kiro-cli 2.25.0")); err != nil {
		t.Fatalf("verify after the repair: %v", err)
	}

	if _, err := Install(context.Background(), kiroStandaloneInstallOptions(home, "kiro-cli 2.20.0")); err == nil ||
		!strings.Contains(err.Error(), "below the certified minimum 2.24.1") {
		t.Fatalf("install below the floor = %v, want the certified-minimum refusal", err)
	}
}

// Outside the standalone profile nothing changes: the floor does not apply
// and a version change is still refused as drift.
func TestKiroFloorIsStandaloneOnly(t *testing.T) {
	skipIfRoot(t)
	t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "")
	setStandaloneProfileForTest(t, false)
	home := newTestHome(t)
	if _, err := Install(context.Background(), kiroStandaloneInstallOptions(home, "kiro-cli 2.20.0")); err != nil {
		t.Fatalf("install below the standalone floor outside the standalone profile: %v", err)
	}
	if _, err := Install(context.Background(), kiroStandaloneInstallOptions(home, "kiro-cli 2.25.0")); err == nil ||
		!strings.Contains(err.Error(), "hook contract drift detected") {
		t.Fatalf("version change outside the standalone profile = %v, want the drift refusal", err)
	}
}

// A known Kiro row that met the floor does not follow a downgrade below it;
// the enumerator keeps it at its last certified version and reports the
// installed one.
func TestUnixKnownKiroRowDoesNotFollowADowngradeBelowTheFloor(t *testing.T) {
	if refused := unixKnownRowVersionRefused("kiro", "kiro-cli 2.24.1", "kiro-cli 2.25.0"); refused != "" {
		t.Fatalf("upgrade refused: %s", refused)
	}
	if refused := unixKnownRowVersionRefused("kiro", "kiro-cli 2.24.1", "kiro-cli 2.20.0"); !strings.Contains(refused, "below the certified minimum 2.24.1") {
		t.Fatalf("downgrade below the floor = %q, want the certified-minimum reason", refused)
	}
	if refused := unixKnownRowVersionRefused("kiro", "kiro-cli 2.19.0", "kiro-cli 2.20.0"); refused != "" {
		t.Fatalf("a row below the floor has nothing certified to keep, got %q", refused)
	}
}

// A Kiro user enrolled by an earlier release below the certified minimum
// (there was no floor then) keeps a hook contract lock. The floor gates new
// enrollments only: the guardian keeps repairing that user's hooks at the
// same version instead of refusing the row, which would make the gateway
// refuse the user's hook calls. A version change below the floor is still
// refused as drift, and an upgrade to the floor is followed.
func TestStandaloneKiroKeepsRepairingARowEnrolledBelowTheFloor(t *testing.T) {
	skipIfRoot(t)
	t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "")
	setStandaloneProfileForTest(t, true)
	home := newTestHome(t)

	// The earlier release's install: no floor applied, so it wrote a lock.
	earlier := kiroStandaloneInstallOptions(home, "kiro-cli 2.22.0")
	t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "1")
	if _, err := Install(context.Background(), earlier); err != nil {
		t.Fatalf("earlier install: %v", err)
	}
	t.Setenv("DEFENSECLAW_ALLOW_HOOK_CONTRACT_DRIFT", "")

	if _, err := Install(context.Background(), kiroStandaloneInstallOptions(home, "kiro-cli 2.22.0")); err != nil {
		t.Fatalf("repair of a row enrolled below the floor: %v", err)
	}
	if _, err := Verify(context.Background(), kiroStandaloneInstallOptions(home, "kiro-cli 2.22.0")); err != nil {
		t.Fatalf("verify of a row enrolled below the floor: %v", err)
	}
	if _, err := Install(context.Background(), kiroStandaloneInstallOptions(home, "kiro-cli 2.23.0")); err == nil ||
		!strings.Contains(err.Error(), "hook contract drift detected") {
		t.Fatalf("a version change below the floor = %v, want the drift refusal", err)
	}
	if _, err := Install(context.Background(), kiroStandaloneInstallOptions(home, "kiro-cli 2.24.1")); err != nil {
		t.Fatalf("upgrade to the floor: %v", err)
	}

	// A new enrollment below the floor is still refused.
	fresh := newTestHome(t)
	if _, err := Install(context.Background(), kiroStandaloneInstallOptions(fresh, "kiro-cli 2.22.0")); err == nil ||
		!strings.Contains(err.Error(), "below the certified minimum 2.24.1") {
		t.Fatalf("new enrollment below the floor = %v, want the certified-minimum refusal", err)
	}
}
