// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestRefusePerUserGatewayOnManagedHost(t *testing.T) {
	descriptor := filepath.Join(t.TempDir(), "managed-runtime.json")
	restore, restoreWindows := managedHostDescriptorPath, managedHostWindowsStandalone
	managedHostDescriptorPath = func() string { return descriptor }
	managedHostWindowsStandalone = func() (string, bool) { return "", false }
	defer func() { managedHostDescriptorPath, managedHostWindowsStandalone = restore, restoreWindows }()
	t.Setenv(managed.DeploymentModeEnv, "")

	if err := refusePerUserGatewayOnManagedHost(); err != nil {
		t.Fatalf("unmanaged host refused: %v", err)
	}
	if err := os.WriteFile(descriptor, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := refusePerUserGatewayOnManagedHost()
	if err == nil || !strings.Contains(err.Error(), "managed by your organization") {
		t.Fatalf("managed host allowed a per-user gateway: %v", err)
	}
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	if err := refusePerUserGatewayOnManagedHost(); err != nil {
		t.Fatalf("managed service refused: %v", err)
	}
}

func TestRefusePerUserGatewayOnWindowsStandaloneHost(t *testing.T) {
	restore, restoreWindows := managedHostDescriptorPath, managedHostWindowsStandalone
	managedHostDescriptorPath = func() string { return "" }
	defer func() { managedHostDescriptorPath, managedHostWindowsStandalone = restore, restoreWindows }()
	t.Setenv(managed.DeploymentModeEnv, "")

	managedHostWindowsStandalone = func() (string, bool) { return "", false }
	if err := refusePerUserGatewayOnManagedHost(); err != nil {
		t.Fatalf("a host without a standalone deployment refused: %v", err)
	}
	managedHostWindowsStandalone = func() (string, bool) {
		return `C:\ProgramData\Cisco\DefenseClaw\install\deployment.json`, true
	}
	err := refusePerUserGatewayOnManagedHost()
	if err == nil || !strings.Contains(err.Error(), "enterprise windows status") {
		t.Fatalf("a Windows standalone host allowed a per-user gateway: %v", err)
	}
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	if err := refusePerUserGatewayOnManagedHost(); err != nil {
		t.Fatalf("the managed gateway service refused: %v", err)
	}
}
