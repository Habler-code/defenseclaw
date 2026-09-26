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
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

func windowsSecretTestHarness(t *testing.T) string {
	t.Helper()
	root := strings.TrimSpace(os.Getenv("DC_M5B_WINDOWS_SECRET_ROOT"))
	if root == "" || !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token and DC_M5B_WINDOWS_SECRET_ROOT: an administrator-only directory on NTFS")
	}
	dir := filepath.Join(root, "secrets")
	_ = os.RemoveAll(dir)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	previousLayout, previousAccount := windowsSecretLayout, windowsSecretGatewayAccount
	previousInstalled, previousElevated, previousRestart := windowsSecretDeploymentInstalled, windowsSecretIsElevated, windowsSecretRestartGateway
	t.Cleanup(func() {
		windowsSecretLayout, windowsSecretGatewayAccount = previousLayout, previousAccount
		windowsSecretDeploymentInstalled, windowsSecretIsElevated, windowsSecretRestartGateway = previousInstalled, previousElevated, previousRestart
	})
	windowsSecretLayout = func() (managed.StandaloneLayout, error) {
		return managed.StandaloneLayout{GOOS: "windows", SecretsDir: dir}, nil
	}
	// A virtual service account that always exists stands in for the
	// gateway service.
	windowsSecretGatewayAccount = `NT SERVICE\TrustedInstaller`
	windowsSecretDeploymentInstalled = func() (bool, error) { return true, nil }
	windowsSecretRestartGateway = func() (bool, error) { return true, nil }
	return dir
}

func runWindowsSecretCommand(t *testing.T, action string, opts enterpriseSecretOptions, stdin string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	cmd.SetIn(strings.NewReader(stdin))
	err := runEnterpriseSecret(cmd, action, &opts)
	return out.String(), err
}

func TestWindowsSecretStoreUsesTheGatewayReaderDACL(t *testing.T) {
	dir := windowsSecretTestHarness(t)
	const value = "aid-test-key-0123456789"
	out, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ai-defense-api-key", fromStdin: true, json: true}, value+"\r\n")
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if strings.Contains(out, value) {
		t.Fatal("the credential value was printed")
	}
	var result map[string]any
	if err := json.Unmarshal([]byte(out), &result); err != nil || result["ok"] != true || result["gateway_restarted"] != true {
		t.Fatalf("set result %s (%v)", out, err)
	}

	path := filepath.Join(dir, "ai-defense-api-key")
	extended, _ := winpath.Extended(path)
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	control, _, _ := sd.Control()
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("the credential DACL inherits from its parent")
	}
	dacl, _, _ := sd.DACL()
	gateway, _ := managed.WindowsServiceAccountSID(windowsSecretGatewayAccount)
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	admins, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	seen := map[string]windows.ACCESS_MASK{}
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			t.Fatal(err)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		seen[sid.String()] = ace.Mask
	}
	if len(seen) != 3 || seen[system.String()] == 0 || seen[admins.String()] == 0 || seen[gateway.String()] == 0 {
		t.Fatalf("credential DACL principals %v", seen)
	}
	if seen[gateway.String()]&(windows.FILE_WRITE_DATA|windows.DELETE|windows.WRITE_DAC) != 0 {
		t.Fatalf("the gateway SID may modify the credential: %#x", seen[gateway.String()])
	}

	t.Setenv(managed.WindowsServiceAccountEnv, windowsSecretGatewayAccount)
	got, source, err := managed.ResolveServiceCredential("ai-defense-api-key", dir)
	if err != nil || string(got) != value || source != managed.CredentialFromFile {
		t.Fatalf("the gateway reader rejected the stored credential: %q %s %v", got, source, err)
	}

	status, err := runWindowsSecretCommand(t, "status", enterpriseSecretOptions{json: true}, "")
	if err != nil || !strings.Contains(status, `"ai-defense-api-key"`) || strings.Contains(status, value) {
		t.Fatalf("status %s %v", status, err)
	}
	if _, err := runWindowsSecretCommand(t, "remove", enterpriseSecretOptions{name: "ai-defense-api-key"}, ""); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("credential still present: %v", err)
	}
}

func TestWindowsSecretRefusals(t *testing.T) {
	windowsSecretTestHarness(t)
	if _, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "../escape", fromStdin: true}, "x"); err == nil || commandExitCode(err) != windowsSecretExitInvalid {
		t.Fatalf("an unsafe name must be refused with 1639, got %v", err)
	}
	if _, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ok-name", fromStdin: true}, "two\nlines"); err == nil {
		t.Fatal("a multi-line credential must be refused")
	}
	windowsSecretDeploymentInstalled = func() (bool, error) { return false, nil }
	if _, err := runWindowsSecretCommand(t, "set", enterpriseSecretOptions{name: "ok-name", fromStdin: true}, "x"); err == nil {
		t.Fatal("set without a standalone deployment must be refused")
	}
	windowsSecretIsElevated = func() bool { return false }
	if _, err := runWindowsSecretCommand(t, "status", enterpriseSecretOptions{}, ""); err == nil || commandExitCode(err) != windowsSecretExitFailure {
		t.Fatalf("a non-elevated token must be refused, got %v", err)
	}
}
