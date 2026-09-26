//go:build !windows && !linux

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"os"
	"strings"
	"testing"
)

// A root guardian re-executes its own image as the target worker, so on
// platforms without /proc/self/exe the image and every directory above it
// must be trusted before it is used. The test binary lives in a directory
// owned by the (unprivileged) test account, so a root guardian must refuse it.
func TestDefaultTargetWorkerExecutableRequiresTrustedImageForRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("the test binary location may be trusted when running as root")
	}
	stubTargetProcessEUID(t, 0)
	executable, _, err := defaultTargetWorkerExecutable()
	if err == nil {
		t.Fatalf("root guardian accepted an untrusted worker image %q", executable)
	}
	if !strings.Contains(err.Error(), "enterprise target worker executable") {
		t.Fatalf("error = %v, want the worker executable trust check", err)
	}

	stubTargetProcessEUID(t, os.Geteuid())
	if _, _, err := defaultTargetWorkerExecutable(); err != nil {
		t.Fatalf("an unprivileged guardian (worker for itself) was refused: %v", err)
	}
}
