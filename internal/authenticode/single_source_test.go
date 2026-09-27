// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package authenticode

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The signer of a WinVerifyTrust result is read only by this package, so
// the Secure Client IPC peer check and the CMID broker cannot drift apart
// in how they find the certificate they compare with the publisher.
func TestWinVerifyTrustSignerIsReadOnlyByThisPackage(t *testing.T) {
	root := filepath.Join("..", "..")
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		// A test binary copied to a test host runs without the sources.
		t.Skipf("module source tree is not available: %v", err)
	}
	self := filepath.Join(root, "internal", "authenticode")
	var found []string
	for _, tree := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, tree), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if path == self {
					return fs.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") {
				return nil
			}
			source, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			for _, export := range []string{
				"WTHelperProvDataFromStateData",
				"WTHelperGetProvSignerFromChain",
				"WTHelperGetProvCertFromChain",
			} {
				if bytes.Contains(source, []byte(export)) {
					found = append(found, path+": "+export)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(found) != 0 {
		t.Fatalf("WinVerifyTrust signer is read outside internal/authenticode; use authenticode.VerifyFile:\n%s",
			strings.Join(found, "\n"))
	}
}
