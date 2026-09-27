// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
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
