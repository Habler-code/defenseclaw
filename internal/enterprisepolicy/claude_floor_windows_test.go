//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// windowsFloorOptions roots Program Files and ProgramData in a protected
// temp tree and stands in for the lifecycle's Claude Code policy lock.
func windowsFloorOptions(t *testing.T) (Options, *int) {
	t.Helper()
	opts := windowsTestOptions(t)
	root := filepath.Dir(opts.WindowsProgramData)
	programFiles := filepath.Join(root, "ProgramFiles")
	if err := createProtectedDir(programFiles); err != nil {
		t.Fatal(err)
	}
	testWindowsTrust(t, root)
	opts.WindowsProgramFiles = programFiles
	withHigherSources(t)
	locked := 0
	previous := windowsClaudeFloorTransaction
	windowsClaudeFloorTransaction = func(fn func(string) error) error {
		locked++
		return fn(filepath.Join(programFiles, "ClaudeCode", "managed-settings.d"))
	}
	t.Cleanup(func() { windowsClaudeFloorTransaction = previous })
	return opts, &locked
}

func TestWindowsClaudeVersionFloorPublishWithdrawAndRemove(t *testing.T) {
	opts, locked := windowsFloorOptions(t)
	if _, err := PublishWindowsClaudeVersionFloor(opts, []string{"codex"}); err != nil || *locked != 0 {
		t.Fatalf("an inactive claudecode with no floor takes no lock: %v locked=%d", err, *locked)
	}
	state, err := PublishWindowsClaudeVersionFloor(opts, []string{"claudecode"})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(opts.WindowsProgramFiles, "ClaudeCode", "managed-settings.d", "00-defenseclaw-version-floor.json")
	if got := readFile(t, path); got != wantClaudeFloorBytes || !state.Changed || *locked != 1 {
		t.Fatalf("floor = %q changed=%v locked=%d", got, state.Changed, *locked)
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(path), DefenseClawDropInName)); !os.IsNotExist(err) {
		t.Fatalf("the Windows floor pass must never write the lifecycle's hook drop-in: %v", err)
	}
	owner, _ := descriptorOf(t, path)
	if !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		t.Fatalf("floor owner = %s, want Administrators", owner)
	}
	if err := validateTrustedFile(path); err != nil {
		t.Fatalf("the floor must pass the machine policy trust rules: %v", err)
	}

	base := filepath.Join(opts.WindowsProgramFiles, "ClaudeCode", "managed-settings.json")
	admin := `{"requiredMinimumVersion": "2.1.300"}`
	writeFile(t, base, admin)
	if _, err := PublishWindowsClaudeVersionFloor(opts, []string{"claudecode"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) || readFile(t, base) != admin {
		t.Fatalf("an administrator value must win and stay unchanged: %v", err)
	}
	if err := os.Remove(base); err != nil {
		t.Fatal(err)
	}
	if _, err := PublishWindowsClaudeVersionFloor(opts, []string{"claudecode"}); err != nil || readFile(t, path) != wantClaudeFloorBytes {
		t.Fatalf("the floor must return: %v", err)
	}

	if _, err := RemoveWindowsClaudeVersionFloor(opts); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("uninstall must remove the floor: %v", err)
	}
	if recorded, err := ClaudeVersionFloorRecorded(opts); err != nil || recorded {
		t.Fatalf("uninstall must remove the floor record: %v %v", recorded, err)
	}
	before := *locked
	if _, err := RemoveWindowsClaudeVersionFloor(opts); err != nil || *locked != before {
		t.Fatalf("a second removal has nothing to lock: %v", err)
	}
}

func TestWindowsClaudeVersionFloorRefusesOtherPlatforms(t *testing.T) {
	opts := testOptions(t)
	if _, err := PublishWindowsClaudeVersionFloor(opts, []string{"claudecode"}); err == nil {
		t.Fatal("the Windows floor pass must refuse a non-Windows target")
	}
	if _, err := RemoveWindowsClaudeVersionFloor(opts); err == nil {
		t.Fatal("the Windows floor removal must refuse a non-Windows target")
	}
}
