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
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// managedHostWindowsStandalone reports a recorded standalone managed
// deployment. A standard user cannot read the administrator-only record;
// its presence still counts. An uninstalled deployment (tombstone) does not.
// Secure Client hosts are unaffected: their record lives under the Secure
// Client roots, which this profile's inspection never reads.
var managedHostWindowsStandalone = func() (string, bool) {
	deployment, err := winpath.InspectEnterpriseDeployment(managed.ProfileStandalone)
	if err != nil {
		return "", false
	}
	switch deployment.State {
	case winpath.EnterpriseDeploymentInstalled, winpath.EnterpriseDeploymentUnknown:
		return deployment.MetadataPath, true
	}
	return "", false
}
