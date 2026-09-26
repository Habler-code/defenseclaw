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

package winpath

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// enterpriseMetadataLimit bounds the deployment metadata read; the document
// is a few kilobytes.
const enterpriseMetadataLimit = 1 << 20

// TrustedEnterpriseRoots resolves a profile's roots from the protected HKLM
// Program Files and ProgramData registration, never from the caller's
// ProgramFiles/ProgramData environment variables.
func TrustedEnterpriseRoots(profile string) (EnterpriseRoots, error) {
	programFiles, err := TrustedProgramFiles()
	if err != nil {
		return EnterpriseRoots{}, err
	}
	programData, err := TrustedProgramData()
	if err != nil {
		return EnterpriseRoots{}, err
	}
	return EnterpriseRootsFor(profile, programFiles, programData)
}

// InspectEnterpriseDeployment reads one profile's deployment metadata.
func InspectEnterpriseDeployment(profile string) (EnterpriseDeployment, error) {
	roots, err := TrustedEnterpriseRoots(profile)
	if err != nil {
		return EnterpriseDeployment{}, err
	}
	deployment := EnterpriseDeployment{Profile: roots.Profile, MetadataPath: roots.MetadataPath}
	info, err := os.Lstat(roots.MetadataPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		deployment.State = EnterpriseDeploymentAbsent
		return deployment, nil
	case errors.Is(err, os.ErrPermission):
		// A standard user cannot read the administrator-only record. Its
		// presence is still a deployment for profile selection.
		deployment.State = EnterpriseDeploymentUnknown
		return deployment, nil
	case err != nil:
		return EnterpriseDeployment{}, fmt.Errorf("inspect enterprise deployment metadata %s: %w", roots.MetadataPath, err)
	case !info.Mode().IsRegular():
		return EnterpriseDeployment{}, fmt.Errorf("enterprise deployment metadata is not a regular file: %s", roots.MetadataPath)
	}
	file, err := os.Open(roots.MetadataPath)
	if err != nil {
		deployment.State = EnterpriseDeploymentUnknown
		return deployment, nil
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, enterpriseMetadataLimit+1))
	if err != nil || len(body) > enterpriseMetadataLimit {
		deployment.State = EnterpriseDeploymentUnknown
		return deployment, nil
	}
	deployment.State, deployment.ProductVersion = classifyEnterpriseMetadata(body)
	return deployment, nil
}

// ResolveInstalledEnterpriseProfile reports which profile this host carries.
// An installed (or unreadable) record wins; with none, a single uninstall
// tombstone names the profile whose preserved state remains. Both profiles
// installed is a conflict, because they share SCM service names and a host
// carries at most one enterprise deployment. found is false on a host with
// no enterprise metadata at all.
func ResolveInstalledEnterpriseProfile() (profile string, found bool, err error) {
	var live, tombstones []string
	for _, candidate := range []string{EnterpriseProfileSecureClient, EnterpriseProfileStandalone} {
		deployment, err := InspectEnterpriseDeployment(candidate)
		if err != nil {
			return "", false, err
		}
		switch deployment.State {
		case EnterpriseDeploymentInstalled, EnterpriseDeploymentUnknown:
			live = append(live, candidate)
		case EnterpriseDeploymentTombstone:
			tombstones = append(tombstones, candidate)
		}
	}
	switch {
	case len(live) > 1:
		return "", false, errors.New("profile_conflict: both Secure Client and standalone enterprise deployments are recorded on this host")
	case len(live) == 1:
		return live[0], true, nil
	case len(tombstones) == 1:
		return tombstones[0], true, nil
	default:
		return "", false, nil
	}
}
