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
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// Secure Client golden: which profile the Windows enterprise lifecycle runs
// for the inputs the Secure Client Setup sends (no --profile, a config with no
// enterprise block, --broker-binary on mutations) on a host whose only
// recorded deployment, if any, is Secure Client, and how it refuses
// standalone-only inputs. See testdata/secure_client_golden/README.md.
func TestSecureClientGoldenWindowsLifecycleProfileResolution(t *testing.T) {
	previous := windowsEnterpriseDeploymentInspector
	t.Cleanup(func() { windowsEnterpriseDeploymentInspector = previous })

	dir := t.TempDir()
	secureClientConfig := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(secureClientConfig, []byte("config_version: 8\ndeployment_mode: managed_enterprise\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	pinnedConfig := filepath.Join(dir, "pinned.yaml")
	if err := os.WriteFile(pinnedConfig, []byte("deployment_mode: managed_enterprise\nenterprise:\n  profile: secure_client\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const broker = `C:\ProgramData\stage\defenseclaw-cmid-broker.exe`
	secureClient := func(state winpath.EnterpriseDeploymentState) map[string]winpath.EnterpriseDeploymentState {
		return map[string]winpath.EnterpriseDeploymentState{managed.ProfileSecureClient: state}
	}
	cases := []struct {
		name   string
		action string
		states map[string]winpath.EnterpriseDeploymentState
		opts   windowsEnterpriseLifecycleOptions
	}{
		{"fresh_install", "install", nil, windowsEnterpriseLifecycleOptions{brokerBinary: broker, configPath: secureClientConfig}},
		{"fresh_install_deferred_config", "install", nil, windowsEnterpriseLifecycleOptions{brokerBinary: broker, deferredConfig: true}},
		{"fresh_status", "status", nil, windowsEnterpriseLifecycleOptions{}},
		{"installed_upgrade", "upgrade", secureClient(winpath.EnterpriseDeploymentInstalled), windowsEnterpriseLifecycleOptions{brokerBinary: broker, configPath: secureClientConfig}},
		{"installed_repair", "repair", secureClient(winpath.EnterpriseDeploymentInstalled), windowsEnterpriseLifecycleOptions{brokerBinary: broker}},
		{"installed_reconcile", "reconcile", secureClient(winpath.EnterpriseDeploymentInstalled), windowsEnterpriseLifecycleOptions{}},
		{"installed_status", "status", secureClient(winpath.EnterpriseDeploymentInstalled), windowsEnterpriseLifecycleOptions{}},
		{"installed_verify", "verify", secureClient(winpath.EnterpriseDeploymentInstalled), windowsEnterpriseLifecycleOptions{}},
		{"installed_uninstall", "uninstall", secureClient(winpath.EnterpriseDeploymentInstalled), windowsEnterpriseLifecycleOptions{purge: true}},
		{"unreadable_record_status", "status", secureClient(winpath.EnterpriseDeploymentUnknown), windowsEnterpriseLifecycleOptions{}},
		{"tombstone_reinstall", "install", secureClient(winpath.EnterpriseDeploymentTombstone), windowsEnterpriseLifecycleOptions{brokerBinary: broker, configPath: secureClientConfig}},
		{"explicit_secure_client", "install", nil, windowsEnterpriseLifecycleOptions{profile: "Secure_Client", brokerBinary: broker}},
		{"config_pins_secure_client", "upgrade", secureClient(winpath.EnterpriseDeploymentInstalled), windowsEnterpriseLifecycleOptions{configPath: pinnedConfig, brokerBinary: broker}},
		{"certification_scope", "install", secureClient(winpath.EnterpriseDeploymentInstalled), windowsEnterpriseLifecycleOptions{
			brokerBinary: broker,
			installRoot:  `C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw-Cert\0123456789`,
			stateRoot:    `C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw-Cert\0123456789`,
		}},
		{"installed_refuses_standalone_request", "install", secureClient(winpath.EnterpriseDeploymentInstalled), windowsEnterpriseLifecycleOptions{profile: "standalone"}},
		{"refuses_standalone_trust_flags", "install", nil, windowsEnterpriseLifecycleOptions{brokerBinary: broker, trustMode: "hash_pinned"}},
		{"refuses_ensure", "ensure", nil, windowsEnterpriseLifecycleOptions{}},
		{"refuses_unknown_profile", "install", nil, windowsEnterpriseLifecycleOptions{profile: "byod"}},
	}
	record := map[string]map[string]string{}
	for _, tc := range cases {
		states := tc.states
		windowsEnterpriseDeploymentInspector = func(profile string) (winpath.EnterpriseDeployment, error) {
			state, ok := states[profile]
			if !ok {
				state = winpath.EnterpriseDeploymentAbsent
			}
			return winpath.EnterpriseDeployment{Profile: profile, State: state}, nil
		}
		opts := tc.opts
		entry := map[string]string{"action": tc.action}
		if err := resolveWindowsEnterpriseLifecycleProfile(tc.action, &opts); err != nil {
			entry["error"] = err.Error()
		} else {
			entry["profile"] = opts.resolvedProfile
			entry["trust_mode"] = opts.trustMode
			entry["product_version"] = opts.productVersion
		}
		record[tc.name] = entry
	}
	recordSecureClientLifecycleProfileResolutionOnDisk(t, record)
	testenv.CompareSecureClientGoldenJSON(t, "windows/lifecycle_profile_resolution.json", record)
}

// recordSecureClientLifecycleProfileResolutionOnDisk adds the same Secure
// Client inputs against deployment records on disk, read and judged by the
// production record inspector and validator. A standard user can create the
// standalone record path under the default ProgramData ACL, as a file or as
// a folder; neither may block or redirect the Secure Client lifecycle,
// whether an administrator (every mutation, and the Setup) or a standard
// user (Status) runs it. A standalone record an administrator wrote still
// refuses. The scratch directory is writable by the current user, exactly
// like a planted tree, so the production validator judges the planted
// shapes; the records an administrator wrote stand in for the lifecycle's
// administrator-only ACL, which a scratch directory cannot carry.
func recordSecureClientLifecycleProfileResolutionOnDisk(t *testing.T, record map[string]map[string]string) {
	t.Helper()
	previousDeployment := windowsEnterpriseDeploymentInspector
	previousRoots := windowsEnterpriseRecordRoots
	previousRecord := windowsEnterpriseRecordInspector
	previousValidator := windowsEnterpriseRecordValidator
	previousElevated := windowsEnterpriseIsElevated
	t.Cleanup(func() {
		windowsEnterpriseDeploymentInspector = previousDeployment
		windowsEnterpriseRecordRoots = previousRoots
		windowsEnterpriseRecordInspector = previousRecord
		windowsEnterpriseRecordValidator = previousValidator
		windowsEnterpriseIsElevated = previousElevated
	})

	dir := t.TempDir()
	secureClientConfig := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(secureClientConfig, []byte("config_version: 8\ndeployment_mode: managed_enterprise\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeRecord := func(name, body string) string {
		t.Helper()
		path := filepath.Join(dir, name, "install", "deployment.json")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	secureClientRecord := writeRecord("secure-client", `{"schema_version":1,"deployment_mode":"managed_enterprise","installed":true}`)
	standaloneRecord := writeRecord("standalone", `{"schema_version":1,"deployment_mode":"managed_enterprise","installed":true,"profile":"standalone","product_version":"1.2.3"}`)
	plantedFile := writeRecord("planted-file", `{"installed":true,"profile":"standalone"}`)
	plantedFolder := filepath.Join(dir, "planted-folder", "install", "deployment.json")
	if err := os.MkdirAll(plantedFolder, 0o700); err != nil {
		t.Fatal(err)
	}
	administratorWritten := map[string]bool{secureClientRecord: true, standaloneRecord: true}

	var paths map[string]string
	windowsEnterpriseDeploymentInspector = inspectTrustedWindowsEnterpriseDeployment
	windowsEnterpriseRecordRoots = func(profile string) (winpath.EnterpriseRoots, error) {
		roots, err := winpath.EnterpriseRootsFor(profile, `C:\Program Files`, `C:\ProgramData`)
		if err != nil {
			return roots, err
		}
		roots.MetadataPath = filepath.Join(dir, "absent-"+roots.Profile, "install", "deployment.json")
		if path, ok := paths[roots.Profile]; ok {
			roots.MetadataPath = path
		}
		return roots, nil
	}
	windowsEnterpriseRecordInspector = func(profile string) (winpath.EnterpriseDeployment, error) {
		roots, err := windowsEnterpriseRecordRoots(profile)
		if err != nil {
			return winpath.EnterpriseDeployment{}, err
		}
		return winpath.InspectEnterpriseDeploymentAt(roots.Profile, roots.MetadataPath)
	}
	windowsEnterpriseRecordValidator = func(path string) error {
		if administratorWritten[path] {
			return nil
		}
		return windowsEnterpriseRecordValidatorDefault(path)
	}

	const broker = `C:\ProgramData\stage\defenseclaw-cmid-broker.exe`
	install := windowsEnterpriseLifecycleOptions{brokerBinary: broker, configPath: secureClientConfig}
	cases := []struct {
		name     string
		action   string
		paths    map[string]string
		elevated bool
		opts     windowsEnterpriseLifecycleOptions
	}{
		{"planted_standalone_file_install", "install", map[string]string{managed.ProfileStandalone: plantedFile}, true, install},
		{"planted_standalone_file_upgrade", "upgrade", map[string]string{managed.ProfileSecureClient: secureClientRecord, managed.ProfileStandalone: plantedFile}, true, install},
		{"planted_standalone_file_status_standard_user", "status", map[string]string{managed.ProfileSecureClient: secureClientRecord, managed.ProfileStandalone: plantedFile}, false, windowsEnterpriseLifecycleOptions{}},
		{"planted_standalone_folder_install", "install", map[string]string{managed.ProfileStandalone: plantedFolder}, true, install},
		{"planted_standalone_folder_uninstall", "uninstall", map[string]string{managed.ProfileSecureClient: secureClientRecord, managed.ProfileStandalone: plantedFolder}, true, windowsEnterpriseLifecycleOptions{purge: true}},
		{"planted_standalone_folder_status_standard_user", "status", map[string]string{managed.ProfileSecureClient: secureClientRecord, managed.ProfileStandalone: plantedFolder}, false, windowsEnterpriseLifecycleOptions{}},
		{"secure_client_record_verify", "verify", map[string]string{managed.ProfileSecureClient: secureClientRecord}, true, windowsEnterpriseLifecycleOptions{}},
		{"administrator_standalone_record_status", "status", map[string]string{managed.ProfileSecureClient: secureClientRecord, managed.ProfileStandalone: standaloneRecord}, true, windowsEnterpriseLifecycleOptions{}},
		{"administrator_standalone_record_install", "install", map[string]string{managed.ProfileStandalone: standaloneRecord}, true, install},
	}
	for _, tc := range cases {
		paths = tc.paths
		elevated := tc.elevated
		windowsEnterpriseIsElevated = func() bool { return elevated }
		opts := tc.opts
		entry := map[string]string{"action": tc.action}
		if err := resolveWindowsEnterpriseLifecycleProfile(tc.action, &opts); err != nil {
			entry["error"] = strings.ReplaceAll(err.Error(), dir, `%Scratch%`)
		} else {
			entry["profile"] = opts.resolvedProfile
			entry["trust_mode"] = opts.trustMode
			entry["product_version"] = opts.productVersion
		}
		entry["ignored_records"] = strconv.Itoa(len(opts.ignoredDeploymentRecords))
		record[tc.name] = entry
	}
}
