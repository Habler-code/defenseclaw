// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The Agent CLI build the cursor-hooks-v1 contract pins, and a later build
// it does not.
const (
	testCursorAgentReviewedBuild   = "2026.07.23-e383d2b"
	testCursorAgentUnreviewedBuild = "2026.09.26-dd393fe"
)

// writeWindowsCursorAgentBuild creates one Cursor Agent CLI build directory
// the way Cursor's Windows installer lays it out, with the given files.
func writeWindowsCursorAgentBuild(t *testing.T, home, build string, leaves ...string) {
	t.Helper()
	dir := filepath.Join(home, "AppData", "Local", "cursor-agent", "versions", build)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, leaf := range leaves {
		if err := os.WriteFile(filepath.Join(dir, leaf), []byte("fixture"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// cursorAgentCLIProfile is a profile with only the native Cursor Agent CLI.
func cursorAgentCLIProfile(t *testing.T, build string) string {
	t.Helper()
	home := t.TempDir()
	writeWindowsCursorAgentBuild(t, home, build, "node.exe", "index.js")
	return home
}

func stubCursorMachinePolicyPublished(t *testing.T, published bool) {
	t.Helper()
	previous := windowsCursorMachinePolicyPublished
	t.Cleanup(func() { windowsCursorMachinePolicyPublished = previous })
	windowsCursorMachinePolicyPublished = func() bool { return published }
}

// The probe picks the build the launchers run: the newest date among the
// directories named like builds, in either name form, and only when that
// build holds the files the launcher starts.
func TestDiscoverWindowsCursorAgentCLIVersionFollowsTheLauncher(t *testing.T) {
	home := t.TempDir()
	if version, reason := discoverWindowsCursorAgentCLIVersion(home); version != "" || reason != "no Cursor Agent CLI under this profile" {
		t.Fatalf("empty profile: version=%q reason=%q", version, reason)
	}

	writeWindowsCursorAgentBuild(t, home, testCursorAgentReviewedBuild, "node.exe", "index.js")
	writeWindowsCursorAgentBuild(t, home, testCursorAgentUnreviewedBuild, "node.exe", "index.js")
	writeWindowsCursorAgentBuild(t, home, "2026.9.3-ab12", "node.exe", "index.js") // older, single-digit month and day
	writeWindowsCursorAgentBuild(t, home, "2027.01.01", "node.exe", "index.js")    // no commit: not a build name
	writeWindowsCursorAgentBuild(t, home, "latest", "node.exe", "index.js")
	versions := filepath.Join(home, "AppData", "Local", "cursor-agent", "versions")
	if err := os.WriteFile(filepath.Join(versions, "2027.02.02-abc"), []byte("a file, not a build"), 0o644); err != nil {
		t.Fatal(err)
	}
	if version, reason := discoverWindowsCursorAgentCLIVersion(home); version != testCursorAgentUnreviewedBuild {
		t.Fatalf("version=%q reason=%q, want the newest build %s", version, reason, testCursorAgentUnreviewedBuild)
	}

	const timestamped = "2026.10.02-10-11-12-beef01"
	writeWindowsCursorAgentBuild(t, home, timestamped, "node.exe", "index.js")
	if version, _ := discoverWindowsCursorAgentCLIVersion(home); version != timestamped {
		t.Fatalf("version=%q, want the timestamped build %s", version, timestamped)
	}

	// The launcher runs the newest build even when it is broken, so an older
	// complete build is not what runs.
	const broken = "2026.11.05-cafe"
	writeWindowsCursorAgentBuild(t, home, broken, "node.exe")
	version, reason := discoverWindowsCursorAgentCLIVersion(home)
	if version != "" || reason != fmt.Sprintf("the newest Cursor Agent CLI build %s has no index.js", broken) {
		t.Fatalf("broken newest build: version=%q reason=%q", version, reason)
	}
}

func TestDiscoverWindowsCursorAgentCLIVersionRefusesAJunctionedInstall(t *testing.T) {
	home := t.TempDir()
	outside := t.TempDir()
	writeWindowsCursorAgentBuild(t, outside, testCursorAgentReviewedBuild, "node.exe", "index.js")
	root := filepath.Join(home, "AppData", "Local")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "cursor-agent")
	target := filepath.Join(outside, "AppData", "Local", "cursor-agent")
	if output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Skipf("junction unavailable: %v: %s", err, output)
	}
	version, reason := discoverWindowsCursorAgentCLIVersion(home)
	if version != "" || reason != "the Cursor Agent CLI install has a refused reparse chain" {
		t.Fatalf("junctioned install: version=%q reason=%q", version, reason)
	}
}

func TestDiscoverWindowsCursorAgentCLIVersionBoundsTheVersionsDirectory(t *testing.T) {
	home := t.TempDir()
	for index := 0; index <= windowsCursorAgentMaxVersionEntries; index++ {
		writeWindowsCursorAgentBuild(t, home, fmt.Sprintf("2026.01.01-%x", index+0x100))
	}
	version, reason := discoverWindowsCursorAgentCLIVersion(home)
	if version != "" || reason != "the Cursor Agent CLI versions directory exceeds the bounded entry count" {
		t.Fatalf("oversized versions directory: version=%q reason=%q", version, reason)
	}
}

// Standalone discovery finds the Agent CLI after Cursor Desktop; the Secure
// Client probe is unchanged and still looks only for Cursor Desktop.
func TestStandaloneDiscoveryFindsTheCursorAgentCLIAfterCursorDesktop(t *testing.T) {
	stubMachineWinGet(t, nil)
	cli := cursorAgentCLIProfile(t, testCursorAgentReviewedBuild)
	if version, reason := standaloneWindowsAgentVersionExplain(cli, "cursor"); version != testCursorAgentReviewedBuild {
		t.Fatalf("Agent CLI only: version=%q reason=%q", version, reason)
	}
	if version, _ := windowsAgentVersionExplain(cli, "cursor"); version != "" {
		t.Fatalf("the Secure Client probe found %q; it must stay Cursor Desktop only", version)
	}

	both := cursorAgentCLIProfile(t, testCursorAgentUnreviewedBuild)
	writeWindowsAgentPackageJSON(t, filepath.Join(both, "AppData", "Local", "Programs", "cursor", "resources", "app"), "3.2.0")
	if version, _ := standaloneWindowsAgentVersionExplain(both, "cursor"); version != "3.2.0" {
		t.Fatalf("Desktop and Agent CLI: version=%q, want the Desktop version", version)
	}

	version, reason := standaloneWindowsAgentVersionExplain(t.TempDir(), "cursor")
	if version != "" || !strings.Contains(reason, "no cursor package.json under this profile") || !strings.Contains(reason, "no Cursor Agent CLI under this profile") {
		t.Fatalf("no Cursor: version=%q reason=%q, want both probes named", version, reason)
	}
}

// A user with only the reviewed Agent CLI build gets a Cursor row, so the
// guardian publishes Cursor's machine hooks file; the Secure Client
// enumerator still ignores the Agent CLI.
func TestEnumerateWindowsStandaloneEnrollsTheReviewedCursorAgentCLIBuild(t *testing.T) {
	stubMachineWinGet(t, nil)
	stubActiveSessions(t, nil)
	stubCursorMachinePolicyPublished(t, false)
	injectWindowsProfileList(t, map[string]string{testLocalUserSID: cursorAgentCLIProfile(t, testCursorAgentReviewedBuild)})
	var reported []UnprotectedAgent
	manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("cursor"), EnumerateOptions{
		ReportUnprotected: func(agent UnprotectedAgent) { reported = append(reported, agent) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Targets) != 1 || len(reported) != 0 {
		t.Fatalf("targets = %+v reported = %+v, want one Cursor row and no report", manifest.Targets, reported)
	}
	row := manifest.Targets[0]
	if row.SID != testLocalUserSID || row.Connector != "cursor" || row.AgentVersion != testCursorAgentReviewedBuild ||
		!row.IsEnabled() || !row.Deferred {
		t.Fatalf("row = %+v, want an enabled deferred Cursor row at %s", row, testCursorAgentReviewedBuild)
	}

	manifest, err = EnumerateWindows(context.Background(), secureClientEnumeratorConfig("cursor"), EnumerateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Targets) != 0 {
		t.Fatalf("Secure Client targets = %+v, want none for an Agent CLI install", manifest.Targets)
	}
}

// An Agent CLI build without a reviewed hook contract is not enrolled and is
// reported, saying whether Cursor's machine hooks are in force for it.
func TestEnumerateWindowsReportsAnUnreviewedCursorAgentCLIBuild(t *testing.T) {
	stubMachineWinGet(t, nil)
	stubActiveSessions(t, nil)
	for _, tc := range []struct {
		published   bool
		consequence string
	}{
		{false, windowsCursorUnpublishedConsequence},
		{true, "its machine-policy hooks refuse this user's tool calls until it is enrolled"},
	} {
		stubCursorMachinePolicyPublished(t, tc.published)
		home := cursorAgentCLIProfile(t, testCursorAgentUnreviewedBuild)
		injectWindowsProfileList(t, map[string]string{testLocalUserSID: home})
		var reported []UnprotectedAgent
		manifest, err := EnumerateWindows(context.Background(), standaloneEnumeratorConfig("cursor"), EnumerateOptions{
			ReportUnprotected: func(agent UnprotectedAgent) { reported = append(reported, agent) },
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(manifest.Targets) != 0 || len(reported) != 1 {
			t.Fatalf("published=%t: targets = %+v reported = %+v, want no row and one report", tc.published, manifest.Targets, reported)
		}
		agent := reported[0]
		if agent.Connector != "cursor" || agent.Version != testCursorAgentUnreviewedBuild ||
			agent.Code != UnprotectedCodeHookContractUnverified || agent.User != filepath.Base(home) {
			t.Fatalf("published=%t: reported = %+v", tc.published, agent)
		}
		want := "version " + testCursorAgentUnreviewedBuild + " is " + standaloneContractRefusal + "; " + tc.consequence
		if agent.Reason != want {
			t.Fatalf("published=%t: reason = %q, want %q", tc.published, agent.Reason, want)
		}
	}
}

// With no Cursor policy on disk the machine hooks are not in force; a root
// that cannot be validated keeps the fail-closed wording.
func TestWindowsCursorMachinePolicyPublishedReadsTheCursorPolicy(t *testing.T) {
	original := windowsCursorManagedRootResolver
	t.Cleanup(func() { windowsCursorManagedRootResolver = original })

	root := filepath.Join(t.TempDir(), "Cursor")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	windowsCursorManagedRootResolver = func() (string, error) { return root, nil }
	if windowsCursorMachinePolicyPublished() {
		t.Fatal("an empty Cursor enterprise directory must not count as a published policy")
	}

	windowsCursorManagedRootResolver = func() (string, error) { return filepath.Join(t.TempDir(), "NotCursor"), nil }
	if !windowsCursorMachinePolicyPublished() {
		t.Fatal("a Cursor policy that cannot be read must keep the fail-closed wording")
	}
}
