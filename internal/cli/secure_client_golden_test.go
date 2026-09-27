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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// TestSecureClientGoldenDotEnvProfilePin pins that a .env file in the data
// directory cannot supply the enterprise profile pin. Secure Client services
// never carry the pin, so a writable .env line would otherwise become it and
// move a Secure Client gateway onto the standalone decision stack. The
// resolution is computed for both Secure Client platforms, so the golden is
// platform independent. See testdata/secure_client_golden/README.md.
func TestSecureClientGoldenDotEnvProfilePin(t *testing.T) {
	unsetEnvironmentForDotenvTest(t, managed.EnterpriseProfileEnv, managed.DeploymentModeEnv)
	path := filepath.Join(t.TempDir(), ".env")
	body := []byte(managed.EnterpriseProfileEnv + "=" + managed.ProfileStandalone + "\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write dotenv: %v", err)
	}

	loadDotEnvIntoOS(path)

	pin, pinLoaded := os.LookupEnv(managed.EnterpriseProfileEnv)
	result := map[string]any{
		"dotenv_profile_pin_loaded": pinLoaded,
	}
	resolved := map[string]string{}
	for _, goos := range []string{"darwin", "windows"} {
		// The Secure Client shape: managed_enterprise, no enterprise block.
		profile, err := managed.ResolveEnterpriseProfile(goos, managed.DeploymentModeManagedEnterprise, pin, "")
		if err != nil {
			resolved[goos] = "error: " + err.Error()
			continue
		}
		resolved[goos] = profile
	}
	result["secure_client_shape_resolves"] = resolved
	testenv.CompareSecureClientGoldenJSON(t, "go/cli_dotenv_profile_pin.json", result)
}

type secureClientCLIScenario struct {
	Scenario string `json:"scenario"`
	Detail   string `json:"detail"`
}

// TestSecureClientGoldenPerUserGatewayGuard pins when a per-user gateway
// refuses to start. The guard only reacts to a standalone deployment record;
// a Secure Client host carries none, so it never refuses there, and a record
// that a standard user could have planted under %ProgramData% does not count
// either.
func TestSecureClientGoldenPerUserGatewayGuard(t *testing.T) {
	descriptor := filepath.Join(t.TempDir(), "managed-runtime.json")
	restore, restoreWindows, restoreTrust := managedHostDescriptorPath, managedHostWindowsStandalone, managedHostRecordTrusted
	defer func() {
		managedHostDescriptorPath, managedHostWindowsStandalone, managedHostRecordTrusted = restore, restoreWindows, restoreTrust
	}()
	managedHostDescriptorPath = func() string { return descriptor }
	managedHostWindowsStandalone = func() (string, bool) { return "", false }

	var rows []secureClientCLIScenario
	guard := func(name, mode string, recordPresent bool, trust error) {
		t.Helper()
		_ = os.Remove(descriptor)
		if recordPresent {
			if err := os.WriteFile(descriptor, []byte("{}"), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		managedHostRecordTrusted = func(string) error { return trust }
		t.Setenv(managed.DeploymentModeEnv, mode)
		rows = append(rows, secureClientCLIScenario{
			Scenario: "per_user_gateway_guard/" + name,
			Detail:   fmt.Sprintf("refused=%t", refusePerUserGatewayOnManagedHost() != nil),
		})
	}
	guard("secure_client_host_no_standalone_record", "", false, nil)
	guard("untrusted_standalone_record", "", true, errors.New("owner is a standard user"))
	guard("trusted_standalone_record", "", true, nil)
	guard("managed_service_pin", managed.DeploymentModeManagedEnterprise, true, nil)

	// A standard user on a Windows standalone host whose vendor directory
	// keeps the ProgramData Users grant cannot trust the record through its
	// ancestors; the administrator-registered gateway service decides, and
	// only when it runs the standalone gateway executable.
	f := newStandaloneGuardFixture()
	windowsGuard := func(name string, service func() (string, error)) {
		t.Helper()
		_ = os.Remove(descriptor)
		t.Setenv(managed.DeploymentModeEnv, "")
		managedHostWindowsStandalone = func() (string, bool) {
			where, err := managedStandaloneRecordCounts(f.record, f.standardUserTrust(userWritableVendorDirectory), service)
			return where, err == nil
		}
		defer func() { managedHostWindowsStandalone = func() (string, bool) { return "", false } }()
		rows = append(rows, secureClientCLIScenario{
			Scenario: "per_user_gateway_guard/" + name,
			Detail:   fmt.Sprintf("refused=%t", refusePerUserGatewayOnManagedHost() != nil),
		})
	}
	windowsGuard("standard_user_user_writable_vendor_standalone_gateway_service", f.service(standaloneGatewayImage, nil))
	windowsGuard("standard_user_user_writable_vendor_no_gateway_service", f.service("", gatewayServiceNotRegistered))
	windowsGuard("standard_user_user_writable_vendor_secure_client_gateway_service", f.service(secureClientGatewayImage, nil))

	root := filepath.Join(string(filepath.Separator), "pd")
	record := filepath.Join(root, "Cisco", "DefenseClaw", "install", "deployment.json")
	denied := &fs.PathError{Op: "inspect", Path: record, Err: fs.ErrPermission}
	for _, test := range []struct {
		name string
		file error
		dir  func(string) error
	}{
		{name: "administrator_record", file: nil},
		{name: "user_owned_record", file: errors.New("owner is a standard user")},
		{
			name: "standard_user_below_administrator_only_directory", file: denied,
			dir: func(dir string) error {
				if dir == filepath.Dir(filepath.Dir(record)) {
					return nil
				}
				return denied
			},
		},
		{
			name: "locked_record_in_user_created_directory", file: denied,
			dir: func(dir string) error {
				if dir == filepath.Dir(record) {
					return errors.New("owner is a standard user")
				}
				return nil
			},
		},
		{name: "nothing_inspectable", file: denied, dir: func(string) error { return denied }},
	} {
		dir := test.dir
		if dir == nil {
			dir = func(string) error { return denied }
		}
		err := managedRecordTrusted(record, root, func(string) error { return test.file }, dir)
		rows = append(rows, secureClientCLIScenario{
			Scenario: "managed_record_trust/" + test.name,
			Detail:   fmt.Sprintf("trusted=%t", err == nil),
		})
	}
	testenv.CompareSecureClientGoldenJSON(t, "go/cli_posture.json", rows)
}
