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
	"fmt"
	"os"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// managedHostWindowsStandalone reports a recorded standalone managed
// deployment. A standard user cannot read the administrator-only record;
// its presence still counts. An uninstalled deployment (tombstone) does not.
// Secure Client hosts are unaffected: their record lives under the Secure
// Client roots, which this profile's inspection never reads.
//
// %ProgramData% lets any user create folders, so a record only counts when
// no one but an administrator could have written it (see
// managedHostRecordTrusted), or when the administrator-registered standalone
// gateway service confirms the deployment (see
// managedStandaloneRecordCounts); otherwise one user could disable every
// other user's per-user gateway by creating the file.
var managedHostWindowsStandalone = func() (string, bool) {
	deployment, err := winpath.InspectEnterpriseDeployment(managed.ProfileStandalone)
	if err != nil {
		return "", false
	}
	switch deployment.State {
	case winpath.EnterpriseDeploymentInstalled, winpath.EnterpriseDeploymentUnknown:
		where, err := managedStandaloneRecordCounts(deployment.MetadataPath, managedHostRecordTrusted, managedHostStandaloneService)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[defenseclaw] ignoring an untrusted managed deployment record: %v\n", err)
			return "", false
		}
		return where, true
	}
	return "", false
}

// managedHostRecordTrusted accepts a managed-deployment record, or runtime
// descriptor, under %ProgramData% only when an administrator must have
// written it. A seam for tests.
var managedHostRecordTrusted = func(path string) error {
	programData, err := winpath.TrustedProgramData()
	if err != nil {
		return err
	}
	return managedRecordTrusted(
		path,
		programData,
		func(file string) error { return managed.ValidateTrustedFilePath(file, "managed deployment record") },
		func(dir string) error { return managed.ValidateTrustedRuntimeDir(dir, "managed deployment directory") },
	)
}

// managedHostStandaloneService describes the standalone gateway service when
// the Service Control Manager has it registered to run
// <Program Files>\Cisco\DefenseClaw\bin\defenseclaw-gateway.exe. Only an
// administrator can register a service. The lifecycle's service DACL grants
// standard users query-config access, so any caller can read the image path.
// The Secure Client profile registers the same service name with its own
// executable; the image path tells them apart. A seam for tests.
var managedHostStandaloneService = func() (string, error) {
	roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
	if err != nil {
		return "", err
	}
	gatewayPath := roots.InstallRoot + `\bin\defenseclaw-gateway.exe`
	image, err := windowsServiceImagePath(managed.StandaloneWindowsGatewaySvc)
	if err != nil {
		return "", err
	}
	if err := standaloneGatewayServiceImageMatches(image, gatewayPath); err != nil {
		return "", fmt.Errorf("service %s: %w", managed.StandaloneWindowsGatewaySvc, err)
	}
	return fmt.Sprintf("service %s runs %s", managed.StandaloneWindowsGatewaySvc, gatewayPath), nil
}

// windowsServiceImagePath reads a service's registered image path with
// connect and query-config access only, which standard users hold.
func windowsServiceImagePath(name string) (string, error) {
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "", fmt.Errorf("connect to the service control manager: %w", err)
	}
	defer windows.CloseServiceHandle(manager)
	namePointer, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}
	service, err := windows.OpenService(manager, namePointer, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return "", fmt.Errorf("open service %s: %w", name, err)
	}
	defer windows.CloseServiceHandle(service)
	var needed uint32
	_ = windows.QueryServiceConfig(service, nil, 0, &needed)
	if needed == 0 || needed > 64<<10 {
		return "", fmt.Errorf("service %s: invalid configuration size %d", name, needed)
	}
	buffer := make([]byte, needed)
	configuration := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buffer[0]))
	if err := windows.QueryServiceConfig(service, configuration, needed, &needed); err != nil {
		return "", fmt.Errorf("query service %s: %w", name, err)
	}
	return windows.UTF16PtrToString(configuration.BinaryPathName), nil
}
