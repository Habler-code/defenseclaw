// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package authenticode

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func openForVerification(t *testing.T, path string) (*uint16, windows.Handle) {
	t.Helper()
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := windows.CreateFile(
		pointer,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL,
		0,
	)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	t.Cleanup(func() { _ = windows.CloseHandle(handle) })
	return pointer, handle
}

// embeddedSignedFile returns a file with an embedded Authenticode
// signature. PowerShell 7 ships Microsoft-signed binaries.
func embeddedSignedFile(t *testing.T) string {
	t.Helper()
	programFiles := os.Getenv("ProgramW6432")
	if programFiles == "" {
		programFiles = os.Getenv("ProgramFiles")
	}
	for _, name := range []string{"pwsh.exe", "hostfxr.dll", "pwsh.dll"} {
		candidate := filepath.Join(programFiles, "PowerShell", "7", name)
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate
		}
	}
	t.Skip("no embedded-Authenticode-signed PowerShell 7 binary is available")
	return ""
}

func TestVerifyFileRejectsAnUnsignedFile(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path, handle := openForVerification(t, executable)
	verification, err := VerifyFile(path, handle)
	if verification == nil {
		t.Fatal("VerifyFile returned no state to close")
	}
	if err == nil {
		t.Fatal("VerifyFile accepted the unsigned test binary")
	}
	_ = verification.Close()
	if err := verification.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestVerifyFileReadsThePrimarySignerLeafCertificate(t *testing.T) {
	signed := embeddedSignedFile(t)
	path, handle := openForVerification(t, signed)
	verification, err := VerifyFile(path, handle)
	defer func() { _ = verification.Close() }()
	if err != nil {
		t.Fatalf("VerifyFile(%s): %v", signed, err)
	}
	leaf, err := verification.PrimarySignerCertificate()
	if err != nil {
		t.Fatalf("PrimarySignerCertificate: %v", err)
	}
	if leaf.EncodedCert == nil || leaf.Length == 0 {
		t.Fatal("primary signer certificate has no encoding")
	}
	certificate, err := x509.ParseCertificate(
		append([]byte(nil), unsafe.Slice(leaf.EncodedCert, leaf.Length)...),
	)
	if err != nil {
		t.Fatalf("parse primary signer certificate: %v", err)
	}
	if certificate.IsCA {
		t.Fatalf("primary signer certificate %q is a CA, want the leaf", certificate.Subject)
	}
	if name := SubjectCommonName(certificate.RawSubject); name == "" {
		t.Fatalf("primary signer certificate %q has no single common name", certificate.Subject)
	}
	if err := verification.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := verification.PrimarySignerCertificate(); err == nil {
		t.Fatal("PrimarySignerCertificate read a closed verification state")
	}
	if err := verification.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
