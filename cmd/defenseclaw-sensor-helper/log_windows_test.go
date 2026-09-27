// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

func TestServiceLogPathReadsProtectedServiceEnvironment(t *testing.T) {
	const path = `C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw\logs\sensor-helper\sensor-helper.log`
	t.Setenv(windowsServiceLogEnv, "  "+path+"  ")
	if got := serviceLogPath(); got != path {
		t.Fatalf("serviceLogPath() = %q, want %q", got, path)
	}
	t.Setenv(windowsServiceLogEnv, "")
	if got := serviceLogPath(); got != "" {
		t.Fatalf("serviceLogPath() = %q with the variable empty, want empty", got)
	}
}

// The lifecycle's AdminDirectory ACL for the sensor-helper log directory:
// Administrators own it, and only LocalSystem and Administrators have any
// access.
const adminDirectorySDDL = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"

// helperLogDirectory creates a directory under the trusted ProgramData root
// with the given descriptor. The opener validates every ancestor, so a user
// profile temp directory cannot stand in for the installer's layout, and
// only an elevated process can hand the directory to Administrators.
func helperLogDirectory(t *testing.T, sddl string) string {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("an administrator-only log directory requires an elevated test process")
	}
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		t.Fatalf("TrustedProgramData: %v", err)
	}
	directory, err := os.MkdirTemp(programData, "defenseclaw-sensor-helper-log-test-")
	if err != nil {
		t.Fatalf("create log test directory: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("parse %q: %v", sddl, err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		t.Fatalf("descriptor owner: %v", err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatalf("descriptor DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(
		directory,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION|
			windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner,
		nil,
		dacl,
		nil,
	); err != nil {
		t.Fatalf("apply %q to %s: %v", sddl, directory, err)
	}
	return directory
}

func TestHelperLogAppendsAcrossRestartsInAdministratorOnlyDirectory(t *testing.T) {
	path := filepath.Join(helperLogDirectory(t, adminDirectorySDDL), "sensor-helper.log")
	var fallback bytes.Buffer
	for _, run := range []string{"first-run", "second-run"} {
		logger, closeLog := newHelperLogger(path, &fallback)
		logger.Error("sensor helper exited", "error", run)
		if run == "second-run" {
			// Support tooling reads the log while the service runs, and
			// nothing else may write to it.
			data, err := os.ReadFile(path)
			if err != nil {
				closeLog()
				t.Fatalf("read the log while the helper holds it: %v", err)
			}
			if !strings.Contains(string(data), "first-run") {
				closeLog()
				t.Fatalf("log read while held = %q, want the earlier run", data)
			}
			if writer, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0); err == nil {
				_ = writer.Close()
				closeLog()
				t.Fatal("a second writer opened the log while the helper held it")
			}
		}
		closeLog()
	}
	if fallback.Len() != 0 {
		t.Fatalf("fallback received output while the service log was usable: %q", fallback.String())
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	first := strings.Index(string(data), "first-run")
	second := strings.Index(string(data), "second-run")
	if first < 0 || second < first || strings.Count(string(data), "sensor helper exited") != 2 {
		t.Fatalf("service log was not appended across restarts: %q", data)
	}
}

func TestHelperLogRejectsUserWritableDirectory(t *testing.T) {
	directory := helperLogDirectory(t, adminDirectorySDDL+"(A;OICI;FA;;;BU)")
	path := filepath.Join(directory, "sensor-helper.log")
	if file, err := openHelperLog(path); err == nil {
		_ = file.Close()
		t.Fatal("openHelperLog accepted a directory that standard users can write")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatalf("rejected log was created anyway: %v", err)
	}
	var fallback bytes.Buffer
	logger, closeLog := newHelperLogger(path, &fallback)
	logger.Error("sensor helper exited", "error", "listen failed")
	closeLog()
	if output := fallback.String(); !strings.Contains(output, "sensor helper log is unavailable") ||
		!strings.Contains(output, "sensor helper exited") {
		t.Fatalf("fallback did not report the unsafe log directory: %q", output)
	}
}

func TestHelperLogRejectsReparsePointLeaf(t *testing.T) {
	directory := helperLogDirectory(t, adminDirectorySDDL)
	target := filepath.Join(directory, "elsewhere.log")
	if err := os.WriteFile(target, []byte("unchanged\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "sensor-helper.log")
	if err := os.Symlink(target, path); err != nil {
		t.Skipf("creating a Windows symlink requires unavailable privilege: %v", err)
	}
	if file, err := openHelperLog(path); err == nil {
		_ = file.Close()
		t.Fatal("openHelperLog followed or accepted a symbolic-link leaf")
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "unchanged\n" {
		t.Fatalf("symbolic-link target changed: %q, %v", data, err)
	}
}

func TestHelperLogRejectsDirectoryLeaf(t *testing.T) {
	path := filepath.Join(helperLogDirectory(t, adminDirectorySDDL), "sensor-helper.log")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if file, err := openHelperLog(path); err == nil {
		_ = file.Close()
		t.Fatal("openHelperLog accepted a directory as the log file")
	}
}

func TestHelperLogRejectsReparsePointDirectory(t *testing.T) {
	directory := helperLogDirectory(t, adminDirectorySDDL)
	trusted := filepath.Join(directory, "trusted")
	if err := os.Mkdir(trusted, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link")
	if err := os.Symlink(trusted, link); err != nil {
		t.Skipf("creating a Windows directory symlink requires unavailable privilege: %v", err)
	}
	if file, err := openHelperLog(filepath.Join(link, "sensor-helper.log")); err == nil {
		_ = file.Close()
		t.Fatal("openHelperLog accepted a log directory reached through a reparse point")
	}
	if _, err := os.Lstat(filepath.Join(trusted, "sensor-helper.log")); !os.IsNotExist(err) {
		t.Fatalf("log was created through the reparse point: %v", err)
	}
}
