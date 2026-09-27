// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

func stageEnsureManifestForEnrollmentTest(t *testing.T, enrollment config.EnterpriseEnrollmentConfig) (int, error) {
	t.Helper()
	previousLoader := windowsEnterpriseEnsureConfigLoader
	previousEnumerator := enterpriseWindowsEnumerateProfileEnumerator
	previousProgramData := windowsEnterpriseProgramDataResolver
	t.Cleanup(func() {
		windowsEnterpriseEnsureConfigLoader = previousLoader
		enterpriseWindowsEnumerateProfileEnumerator = previousEnumerator
		windowsEnterpriseProgramDataResolver = previousProgramData
	})
	windowsEnterpriseEnsureConfigLoader = func(string) (*config.Config, error) {
		return standaloneWindowsEnrollmentConfig(enrollment), nil
	}
	calls := 0
	enterpriseWindowsEnumerateProfileEnumerator = func(context.Context, *config.Config, enterprisehooks.EnumerateOptions) (enterprisehooks.Manifest, error) {
		calls++
		return enterprisehooks.Manifest{}, errors.New("enumeration stopped by the test")
	}
	// Stop before any protected staging directory is created.
	windowsEnterpriseProgramDataResolver = func() (string, error) {
		calls++
		return "", errors.New("staging stopped by the test")
	}
	cmd := &cobra.Command{}
	cmd.SetErr(new(bytes.Buffer))
	_, cleanup, err := stageWindowsEnterpriseEnsureManifest(
		context.Background(),
		cmd,
		filepath.Join(t.TempDir(), "config.yaml"),
	)
	if cleanup != nil {
		cleanup()
	}
	return calls, err
}

// In enterprise.enrollment.mode manifest the installed enumerator stays idle,
// so ensure must not stage a first manifest from discovery that nothing would
// ever update or prune: it needs the administrator's --manifest.
func TestWindowsEnterpriseEnsureRefusesToEnumerateInManifestMode(t *testing.T) {
	calls, err := stageEnsureManifestForEnrollmentTest(t, config.EnterpriseEnrollmentConfig{
		Mode: config.EnterpriseEnrollmentManifest,
	})
	if !errors.Is(err, errWindowsEnterpriseEnsureManifestRequired) {
		t.Fatalf("staging error = %v, want the --manifest requirement", err)
	}
	if calls != 0 {
		t.Fatalf("manifest mode staged or enumerated (%d calls)", calls)
	}
	if code := windowsEnterpriseEnsureStagingErrorCode(err); code != "invalid_arguments" {
		t.Fatalf("manifest-mode refusal code = %q, want invalid_arguments", code)
	}
	if code := windowsEnterpriseEnsureStagingErrorCode(errors.New("disk full")); code != "manifest_staging_failed" {
		t.Fatalf("ordinary staging failure code = %q, want manifest_staging_failed", code)
	}

	calls, err = stageEnsureManifestForEnrollmentTest(t, config.EnterpriseEnrollmentConfig{
		Mode: config.EnterpriseEnrollmentAuto,
	})
	if errors.Is(err, errWindowsEnterpriseEnsureManifestRequired) || calls == 0 {
		t.Fatalf("auto mode must go on to stage the enumerated manifest (err=%v calls=%d)", err, calls)
	}
}
