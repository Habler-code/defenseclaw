// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// deferredPendingProofFixture is a real deferred row for a profile that
// DefenseClaw has never touched: the home exists, its canonical
// %USERPROFILE%\.defenseclaw does not, and no runtime selector is published.
func deferredPendingProofFixture(t *testing.T, standalone bool) ManifestTarget {
	t.Helper()
	targetSID := currentWindowsTestSID(t)
	home := newWindowsTargetOwnedTestHome(t, targetSID)
	// The trust check is stubbed; the proof only needs a canonical path.
	hookExe := filepath.Join(t.TempDir(), "defenseclaw-hook.exe")
	selectorRoot := t.TempDir()

	previousStandalone := windowsEnterpriseStandaloneProcess
	previousHook := windowsEnterpriseHookExecutable
	previousTrust := windowsEnterpriseHookTrustCheck
	previousSelector := windowsManagedRuntimeSelectorPathResolver
	windowsEnterpriseStandaloneProcess = func() bool { return standalone }
	windowsEnterpriseHookExecutable = func() (string, error) { return hookExe, nil }
	windowsEnterpriseHookTrustCheck = func(string) error { return nil }
	windowsManagedRuntimeSelectorPathResolver = func(name string) (string, error) {
		return filepath.Join(selectorRoot, name, windowsManagedRuntimeSelectorFile), nil
	}
	t.Cleanup(func() {
		windowsEnterpriseStandaloneProcess = previousStandalone
		windowsEnterpriseHookExecutable = previousHook
		windowsEnterpriseHookTrustCheck = previousTrust
		windowsManagedRuntimeSelectorPathResolver = previousSelector
	})

	enabled := true
	return ManifestTarget{
		SID:          targetSID.String(),
		UserHome:     home,
		Connector:    "claudecode",
		AgentVersion: "2.1.230",
		Enabled:      &enabled,
		Deferred:     true,
	}
}

func TestStandaloneDeferredPendingProofAcceptsAnAbsentDataDirectory(t *testing.T) {
	target := deferredPendingProofFixture(t, true)
	if _, err := os.Lstat(filepath.Join(target.UserHome, ".defenseclaw")); !os.IsNotExist(err) {
		t.Fatalf("fixture data directory must be absent, got %v", err)
	}
	if err := RequireWindowsEnterpriseDeferredTargetPending(target); err != nil {
		t.Fatalf("standalone pending proof for a never-touched profile failed: %v", err)
	}
}

// WIN-F49: an account that ran an agent before it was enrolled has a
// %USERPROFILE%\.defenseclaw the hook created with the profile's inherited
// DACL. The pending proof must accept it, and enrollment in the account's
// session must adopt it instead of failing every reconcile.
func TestStandaloneDeferredPendingProofAndEnrollmentAdoptAnAccountCreatedDataDirectory(t *testing.T) {
	target := deferredPendingProofFixture(t, true)
	sid := currentWindowsTestSID(t)
	dataDir := filepath.Join(target.UserHome, ".defenseclaw")
	// A junction the account made there, to another folder it owns, is not one.
	elsewhere := filepath.Join(target.UserHome, "elsewhere")
	if err := os.MkdirAll(elsewhere, 0o700); err != nil {
		t.Fatal(err)
	}
	setWindowsTestPathExactOwner(t, elsewhere, sid)
	if output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", dataDir, elsewhere).CombinedOutput(); err != nil {
		t.Fatalf("create junction: %v: %s", err, output)
	}
	setWindowsTestPathExactOwner(t, dataDir, sid)
	if err := RequireWindowsEnterpriseDeferredTargetPending(target); err == nil {
		t.Fatal("the pending proof accepted a junctioned data directory")
	}
	if err := os.Remove(dataDir); err != nil {
		t.Fatal(err)
	}
	logs := filepath.Join(dataDir, "logs")
	if err := os.MkdirAll(logs, 0o700); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(logs, "hook-failures.jsonl")
	if err := os.WriteFile(record, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dataDir, logs, record} {
		setWindowsTestPathExactOwner(t, path, sid)
	}
	if err := RequireWindowsEnterpriseDeferredTargetPending(target); err != nil {
		t.Fatalf("pending proof for an account-created data directory failed: %v", err)
	}
	var creation windowsTargetOwnedDirectoryCreation
	if err := runWindowsTestThreadImpersonatedAsSelf(func() error {
		var err error
		creation, err = ensureWindowsTargetOwnedDirectoryTree(target.UserHome, filepath.Join(dataDir, "hooks"), sid)
		return err
	}); err != nil {
		t.Fatalf("enrollment did not adopt the account-created data directory: %v", err)
	}
	if creation.createdDataDir || !creation.createdHookDir {
		t.Fatalf("adoption creation = %+v, want only the hook directory created", creation)
	}
	assertWindowsTargetOwnedCanonicalDirectory(t, dataDir, sid)
	if _, err := os.Lstat(record); err != nil {
		t.Fatalf("adoption must keep the account's own files: %v", err)
	}
}

func TestSecureClientDeferredPendingProofStillRequiresTheDataDirectory(t *testing.T) {
	target := deferredPendingProofFixture(t, false)
	err := RequireWindowsEnterpriseDeferredTargetPending(target)
	if err == nil || !strings.Contains(err.Error(), "deferred target data directory is untrusted") {
		t.Fatalf("Secure Client pending proof error = %v, want the untrusted data directory refusal", err)
	}
}

func TestStandaloneDeferredPendingProofRejectsADataDirectoryOfTheWrongType(t *testing.T) {
	target := deferredPendingProofFixture(t, true)
	if err := os.WriteFile(filepath.Join(target.UserHome, ".defenseclaw"), []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := RequireWindowsEnterpriseDeferredTargetPending(target)
	if err == nil || !strings.Contains(err.Error(), "deferred target data directory is untrusted") {
		t.Fatalf("pending proof error = %v, want a file in place of the data directory refused", err)
	}
}

func TestStandaloneDeferredPendingProofStillRequiresSelectorAbsence(t *testing.T) {
	target := deferredPendingProofFixture(t, true)
	selector, err := windowsManagedRuntimeSelectorPathResolver("claudecode")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(selector), 0o700); err != nil {
		t.Fatal(err)
	}
	// Any published selector must be read and judged; an unreadable one is an
	// error, never proof of absence.
	if err := os.WriteFile(selector, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RequireWindowsEnterpriseDeferredTargetPending(target); err == nil {
		t.Fatal("pending proof accepted a profile while a runtime selector was published")
	}
}
