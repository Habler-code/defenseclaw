// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// TestWindowsManagedRecordTrustUsesRealACLs checks the guard's validators on
// real NTFS security descriptors: an administrator-owned record in an
// administrator-only tree is trusted, and the same record owned by the Users
// group, as a planted file would be, is not. It needs an elevated shell (to
// set the owner) and a temp directory whose ancestors administrators own.
func TestWindowsManagedRecordTrustUsesRealACLs(t *testing.T) {
	root := t.TempDir()
	icacls := func(args ...string) error {
		out, err := exec.Command("icacls", args...).CombinedOutput()
		if err != nil {
			t.Logf("icacls %v: %v: %s", args, err, out)
		}
		return err
	}
	// Administrator-only tree: SYSTEM and Administrators full control,
	// Users read, nothing inherited from the temp location.
	if err := icacls(root, "/inheritance:r", "/grant:r", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F", "*S-1-5-32-545:(OI)(CI)RX"); err != nil {
		t.Skip("cannot set an administrator-only ACL here")
	}
	if err := managed.ValidateTrustedRuntimeDir(root, "test root"); err != nil {
		t.Skipf("temp root is not under administrator-owned ancestors: %v", err)
	}
	record := filepath.Join(root, "Cisco", "DefenseClaw", "install", "deployment.json")
	if err := os.MkdirAll(filepath.Dir(record), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(record, []byte(`{"state":"installed"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	validateFile := func(path string) error { return managed.ValidateTrustedFilePath(path, "managed deployment record") }
	validateDir := func(dir string) error { return managed.ValidateTrustedRuntimeDir(dir, "managed deployment directory") }
	stop := filepath.Dir(root)
	if err := managedRecordTrusted(record, stop, validateFile, validateDir); err != nil {
		t.Fatalf("an administrator-owned record was not trusted: %v", err)
	}
	if err := icacls(record, "/setowner", "*S-1-5-32-545"); err != nil {
		t.Skip("setting a non-administrator owner needs an elevated shell")
	}
	if err := managedRecordTrusted(record, stop, validateFile, validateDir); err == nil {
		t.Fatal("a record owned by the Users group was trusted")
	}
}

// TestWindowsStandaloneGatewayServiceLookup reads the real Service Control
// Manager with the caller's token, the way the guard does. Run as a standard
// user on a standalone host, it shows that the connect and query-config
// access the guard needs are granted and that the registered image path
// decides. A host without the gateway service must not confirm a deployment.
func TestWindowsStandaloneGatewayServiceLookup(t *testing.T) {
	image, err := windowsServiceImagePath(managed.StandaloneWindowsGatewaySvc)
	if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
		if where, err := managedHostStandaloneService(); err == nil {
			t.Fatalf("an unregistered gateway service confirmed a standalone deployment: %s", where)
		}
		t.Skip("no DefenseClawGateway service on this host")
	}
	if err != nil {
		t.Fatalf("read the gateway service image path: %v", err)
	}
	roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
	if err != nil {
		t.Fatal(err)
	}
	standalone := strings.EqualFold(serviceImageExecutable(image), roots.InstallRoot+`\bin\defenseclaw-gateway.exe`)
	where, err := managedHostStandaloneService()
	if (err == nil) != standalone {
		t.Fatalf("image %q: managedHostStandaloneService = %q, %v; want confirmed=%t", image, where, err, standalone)
	}
	t.Logf("image %q confirmed=%t (%s)", image, err == nil, where)
}
