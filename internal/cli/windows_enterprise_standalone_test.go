// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

func stubWindowsEnterpriseDeployments(t *testing.T, states map[string]winpath.EnterpriseDeploymentState) {
	t.Helper()
	original := windowsEnterpriseDeploymentInspector
	windowsEnterpriseDeploymentInspector = func(profile string) (winpath.EnterpriseDeployment, error) {
		state, ok := states[profile]
		if !ok {
			state = winpath.EnterpriseDeploymentAbsent
		}
		return winpath.EnterpriseDeployment{Profile: profile, State: state}, nil
	}
	t.Cleanup(func() { windowsEnterpriseDeploymentInspector = original })
}

func TestWindowsEnterpriseProfileDefaultsToSecureClientWithUnchangedArguments(t *testing.T) {
	stubWindowsEnterpriseDeployments(t, nil)
	opts := &windowsEnterpriseLifecycleOptions{gatewayBinary: `C:\p\defenseclaw-gateway.exe`, jsonOutput: true}
	before := windowsEnterprisePowerShellArgs("install", opts)
	if err := resolveWindowsEnterpriseLifecycleProfile("install", opts); err != nil {
		t.Fatal(err)
	}
	if opts.resolvedProfile != "secure_client" {
		t.Fatalf("resolved %q", opts.resolvedProfile)
	}
	after := windowsEnterprisePowerShellArgs("install", opts)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("Secure Client arguments changed:\n before %q\n after  %q", before, after)
	}
	for _, arg := range after {
		if strings.Contains(arg, "Profile") || strings.Contains(arg, "TrustMode") || arg == "-ProductVersion" {
			t.Fatalf("Secure Client arguments carry standalone flag %q", arg)
		}
	}
}

func TestWindowsEnterpriseProfileResolution(t *testing.T) {
	for _, tc := range []struct {
		name    string
		states  map[string]winpath.EnterpriseDeploymentState
		opts    windowsEnterpriseLifecycleOptions
		action  string
		want    string
		wantErr string
	}{
		{name: "flag standalone", opts: windowsEnterpriseLifecycleOptions{profile: "Standalone"}, action: "install", want: "standalone"},
		{name: "installed standalone", states: map[string]winpath.EnterpriseDeploymentState{"standalone": winpath.EnterpriseDeploymentInstalled}, action: "status", want: "standalone"},
		{name: "unreadable standalone", states: map[string]winpath.EnterpriseDeploymentState{"standalone": winpath.EnterpriseDeploymentUnknown}, action: "status", want: "standalone"},
		{name: "standalone tombstone", states: map[string]winpath.EnterpriseDeploymentState{"standalone": winpath.EnterpriseDeploymentTombstone}, action: "uninstall", want: "standalone"},
		{name: "secure client tombstone allows standalone", states: map[string]winpath.EnterpriseDeploymentState{"secure_client": winpath.EnterpriseDeploymentTombstone}, opts: windowsEnterpriseLifecycleOptions{profile: "standalone"}, action: "install", want: "standalone"},
		{name: "explicit secure client on standalone host", states: map[string]winpath.EnterpriseDeploymentState{"standalone": winpath.EnterpriseDeploymentInstalled}, opts: windowsEnterpriseLifecycleOptions{profile: "secure_client"}, action: "uninstall", wantErr: "profile_conflict"},
		{name: "standalone on secure client host", states: map[string]winpath.EnterpriseDeploymentState{"secure_client": winpath.EnterpriseDeploymentInstalled}, opts: windowsEnterpriseLifecycleOptions{profile: "standalone"}, action: "install", wantErr: "profile_conflict"},
		{name: "both installed", states: map[string]winpath.EnterpriseDeploymentState{"secure_client": winpath.EnterpriseDeploymentInstalled, "standalone": winpath.EnterpriseDeploymentInstalled}, action: "status", wantErr: "profile_conflict"},
		{name: "certification scope skips detection", states: map[string]winpath.EnterpriseDeploymentState{"secure_client": winpath.EnterpriseDeploymentInstalled}, opts: windowsEnterpriseLifecycleOptions{profile: "standalone", gatewayServiceName: "DefenseClawCertGateway_0a1b2c3d4e"}, action: "install", want: "standalone"},
		{name: "unknown profile", opts: windowsEnterpriseLifecycleOptions{profile: "cloud"}, action: "install", wantErr: "invalid arguments"},
		{name: "broker on standalone", opts: windowsEnterpriseLifecycleOptions{profile: "standalone", brokerBinary: `C:\b.exe`}, action: "install", wantErr: "no CMID credential broker"},
		{name: "trust mode on secure client", opts: windowsEnterpriseLifecycleOptions{trustMode: "hash_pinned"}, action: "install", wantErr: "apply only to the standalone profile"},
		{name: "hash pinned needs manifest", opts: windowsEnterpriseLifecycleOptions{profile: "standalone", trustMode: "hash_pinned"}, action: "install", wantErr: "requires --payload-manifest"},
		{name: "manifest needs hash pinned", opts: windowsEnterpriseLifecycleOptions{profile: "standalone", payloadManifest: `C:\m.json`}, action: "install", wantErr: "applies only to --trust-mode hash_pinned"},
		{name: "bad signer", opts: windowsEnterpriseLifecycleOptions{profile: "standalone", allowedSigners: []string{"abc"}}, action: "install", wantErr: "not a SHA-256"},
		{name: "ensure on secure client", action: "ensure", wantErr: "ensure is available only"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stubWindowsEnterpriseDeployments(t, tc.states)
			opts := tc.opts
			err := resolveWindowsEnterpriseLifecycleProfile(tc.action, &opts)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if opts.resolvedProfile != tc.want {
				t.Fatalf("resolved %q, want %q", opts.resolvedProfile, tc.want)
			}
		})
	}
}

func TestWindowsEnterpriseProfileFromConfig(t *testing.T) {
	stubWindowsEnterpriseDeployments(t, nil)
	dir := t.TempDir()
	standalone := filepath.Join(dir, "standalone.yaml")
	if err := os.WriteFile(standalone, []byte("deployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts := &windowsEnterpriseLifecycleOptions{configPath: standalone}
	if err := resolveWindowsEnterpriseLifecycleProfile("install", opts); err != nil {
		t.Fatal(err)
	}
	if opts.resolvedProfile != "standalone" {
		t.Fatalf("resolved %q", opts.resolvedProfile)
	}
	conflict := &windowsEnterpriseLifecycleOptions{configPath: standalone, profile: "secure_client"}
	if err := resolveWindowsEnterpriseLifecycleProfile("install", conflict); err == nil || !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("flag/config conflict: %v", err)
	}
	plain := filepath.Join(dir, "plain.yaml")
	if err := os.WriteFile(plain, []byte("deployment_mode: managed_enterprise\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opts = &windowsEnterpriseLifecycleOptions{configPath: plain}
	if err := resolveWindowsEnterpriseLifecycleProfile("install", opts); err != nil || opts.resolvedProfile != "secure_client" {
		t.Fatalf("plain config resolved %q, %v", opts.resolvedProfile, err)
	}
}

func TestWindowsEnterpriseStandaloneArguments(t *testing.T) {
	stubWindowsEnterpriseDeployments(t, nil)
	signer := strings.Repeat("AB", 32)
	opts := &windowsEnterpriseLifecycleOptions{
		profile:         "standalone",
		trustMode:       "HASH_PINNED",
		payloadManifest: `C:\stage\payload-trust.json`,
		allowedSigners:  []string{signer, strings.Repeat("cd", 32)},
		productVersion:  "1.4.0",
	}
	if err := resolveWindowsEnterpriseLifecycleProfile("install", opts); err != nil {
		t.Fatal(err)
	}
	args := windowsEnterprisePowerShellArgs("install", opts)
	want := []string{
		"-EnterpriseProfile", "Standalone",
		"-TrustMode", "HashPinned", "-PayloadManifest", `C:\stage\payload-trust.json`,
		"-AllowedSigners", strings.ToLower(signer) + "," + strings.Repeat("cd", 32),
		"-ProductVersion", "1.4.0",
	}
	if got := args[len(args)-len(want):]; !reflect.DeepEqual(got, want) {
		t.Fatalf("standalone tail %q, want %q", got, want)
	}
	defaulted := &windowsEnterpriseLifecycleOptions{profile: "standalone"}
	if err := resolveWindowsEnterpriseLifecycleProfile("status", defaulted); err != nil {
		t.Fatal(err)
	}
	if defaulted.trustMode != "authenticode" || defaulted.productVersion != strings.TrimSpace(appVersion) {
		t.Fatalf("defaults: trust %q version %q", defaulted.trustMode, defaulted.productVersion)
	}
}

func TestParseWindowsEnterprisePayloadManifest(t *testing.T) {
	digest := strings.Repeat("0f", 32)
	pins, err := parseWindowsEnterprisePayloadManifest([]byte(`{"schema_version":1,"files":{"Install-Enterprise.ps1":"` + strings.ToUpper(digest) + `"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if pins["install-enterprise.ps1"] != digest {
		t.Fatalf("pins %v", pins)
	}
	for _, bad := range []string{
		`{"schema_version":2,"files":{"a.exe":"` + digest + `"}}`,
		`{"schema_version":1,"files":{}}`,
		`{"schema_version":1,"files":{"..\\a.exe":"` + digest + `"}}`,
		`{"schema_version":1,"files":{"a.exe":"xyz"}}`,
		`{"schema_version":1,"files":{"a.exe":"` + digest + `"},"extra":1}`,
	} {
		if _, err := parseWindowsEnterprisePayloadManifest([]byte(bad)); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
}

func TestWindowsPowerShell7Selection(t *testing.T) {
	for value, ok := range map[string]bool{"7.4.6": true, "7.5.0": true, "8.0": true, "7.5.0-preview.3": false, "6.2.7": false, "": false, "7": false, "7.x": false} {
		if _, got := parseWindowsPowerShell7Version(value); got != ok {
			t.Fatalf("parse %q = %t", value, got)
		}
	}
	older, _ := parseWindowsPowerShell7Version("7.4.6")
	newer, _ := parseWindowsPowerShell7Version("7.10.0")
	if compareWindowsVersions(newer, older) <= 0 {
		t.Fatal("7.10.0 must sort after 7.4.6")
	}
	for location, want := range map[string]string{
		`C:\Program Files\PowerShell\7\`:  `C:\Program Files\PowerShell\7`,
		`c:\program files\PowerShell\7`:   `c:\program files\PowerShell\7`,
		`C:\Program Files`:                "",
		`C:\Users\x\PowerShell\7`:         "",
		`%ProgramFiles%\PowerShell\7`:     "",
		`C:\Program Files (x86)\PS\7`:     "",
		`C:\Program Files\..\Temp\pwsh\7`: "",
	} {
		got, ok := windowsPowerShell7Home(location, `C:\Program Files`)
		if (want == "") == ok || got != want {
			t.Fatalf("home(%q) = %q, %t; want %q", location, got, ok, want)
		}
	}
}

func TestCompareWindowsEnterpriseVersions(t *testing.T) {
	for _, tc := range []struct {
		left, right string
		want        int
	}{
		{"1.4.0", "1.4.0", 0},
		{"v1.4.1", "1.4.0", 1},
		{"1.4.0", "1.10.0", -1},
		{"1.4.0-rc.1", "1.4.0", -1},
		{"1.4.0+build.7", "1.4.0", 0},
		{"1.4.0", "", 1},
		{"dev", "1.4.0", 1},
	} {
		if got := compareWindowsEnterpriseVersions(tc.left, tc.right); got != tc.want {
			t.Fatalf("compare(%q, %q) = %d, want %d", tc.left, tc.right, got, tc.want)
		}
	}
}

func TestPlanWindowsEnterpriseEnsure(t *testing.T) {
	original := windowsEnterpriseEnsureDriftDetector
	drift := ""
	windowsEnterpriseEnsureDriftDetector = func(*windowsEnterpriseLifecycleOptions, string) (string, error) { return drift, nil }
	t.Cleanup(func() { windowsEnterpriseEnsureDriftDetector = original })
	full := windowsEnterpriseLifecycleOptions{
		profile: "standalone", resolvedProfile: "standalone", productVersion: "1.4.0",
		gatewayBinary: "g", acpBinary: "a", hookBinary: "h", sensorHelperBinary: "s", configPath: "c",
	}
	for _, tc := range []struct {
		name    string
		status  windowsEnterpriseInstallerReport
		opts    windowsEnterpriseLifecycleOptions
		drift   string
		want    string
		wantErr string
	}{
		{name: "pending", status: windowsEnterpriseInstallerReport{Installed: true, TransactionPending: true}, opts: full, want: "repair"},
		{name: "absent", status: windowsEnterpriseInstallerReport{}, opts: full, want: "install"},
		{name: "absent without config", status: windowsEnterpriseInstallerReport{}, opts: windowsEnterpriseLifecycleOptions{productVersion: "1.4.0", gatewayBinary: "g"}, wantErr: "requires --config"},
		{name: "older", status: windowsEnterpriseInstallerReport{Installed: true, InstalledVersion: "1.3.9"}, opts: full, want: "upgrade"},
		{name: "newer", status: windowsEnterpriseInstallerReport{Installed: true, InstalledVersion: "1.5.0"}, opts: full, wantErr: "downgrade_refused"},
		{name: "drift", status: windowsEnterpriseInstallerReport{Installed: true, InstalledVersion: "1.4.0"}, opts: full, drift: "config", want: "upgrade"},
		{name: "compliant", status: windowsEnterpriseInstallerReport{Installed: true, InstalledVersion: "1.4.0"}, opts: full, want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			drift = tc.drift
			opts := tc.opts
			plan, err := planWindowsEnterpriseEnsure(&tc.status, &opts, `C:\stage\install-enterprise.ps1`)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if plan.Action != tc.want {
				t.Fatalf("plan %+v, want %q", plan, tc.want)
			}
		})
	}
}

func TestWindowsEnterpriseStandaloneActionReportsSchemaTwo(t *testing.T) {
	stubWindowsEnterpriseDeployments(t, nil)
	originalRunner := windowsEnterpriseStandaloneRunner
	originalObserver := windowsEnterpriseStandaloneObserver
	originalSC := windowsEnterpriseCommandRunner
	t.Cleanup(func() {
		windowsEnterpriseStandaloneRunner = originalRunner
		windowsEnterpriseStandaloneObserver = originalObserver
		windowsEnterpriseCommandRunner = originalSC
	})
	windowsEnterpriseCommandRunner = func(context.Context, *cobra.Command, string, []string) error {
		t.Fatal("the standalone profile must not use the Windows PowerShell runner")
		return nil
	}
	var gotArgs []string
	windowsEnterpriseStandaloneRunner = func(_ context.Context, _ *cobra.Command, _ string, args []string) (windowsEnterpriseStandaloneRun, error) {
		gotArgs = args
		body, _ := json.Marshal(map[string]any{
			"schema_version": 1, "ok": true, "action": "status", "installed": true,
			"gateway_service": "DefenseClawGateway", "gateway_service_state": "running",
			"guardian_service": "DefenseClawHookGuardian", "guardian_service_state": "running",
			"enumerator_service": "DefenseClawHookEnumerator", "enumerator_service_state": "running",
			"sensor_helper_service": "DefenseClawSensorHelper", "sensor_helper_service_state": "running",
			"gateway_ready": true, "guardian_ready": true, "security_complete": true,
			"installed_version": "1.4.0", "errors": []string{},
		})
		return windowsEnterpriseStandaloneRun{Output: append([]byte("WARNING: noise\n"), body...)}, nil
	}
	windowsEnterpriseStandaloneObserver = func(*enterprisestatus.Result, *windowsEnterpriseLifecycleOptions) string {
		return `C:\Windows\Logs\DefenseClaw\enterprise-lifecycle.log`
	}

	command := &cobra.Command{}
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	command.SetErr(&bytes.Buffer{})
	opts := &windowsEnterpriseLifecycleOptions{profile: "standalone", resolvedProfile: "standalone", productVersion: "1.4.0", jsonOutput: true, trustMode: "authenticode"}
	if err := runWindowsEnterpriseStandaloneAction(context.Background(), command, "status", opts, `C:\x\install-enterprise.ps1`, windowsEnterprisePowerShellArgs("status", opts)); err != nil {
		t.Fatal(err)
	}
	if !containsString(gotArgs, "-Json") || !containsString(gotArgs, "Standalone") {
		t.Fatalf("installer args %q", gotArgs)
	}
	var result enterprisestatus.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatalf("decode %q: %v", stdout.String(), err)
	}
	if result.SchemaVersion != 2 || !result.OK || result.Profile != "standalone" || result.ExitCode != 0 ||
		len(result.Services) != 4 || !result.Readiness.Enumerator || result.InstalledVersion != "1.4.0" ||
		result.LogPath == "" {
		t.Fatalf("result %+v", result)
	}
}

func TestWindowsEnterpriseStandaloneFailureCodes(t *testing.T) {
	for _, tc := range []struct {
		message string
		code    string
		exit    int
	}{
		{"another DefenseClaw enterprise lifecycle mutation holds the protected file lock for more than 30 seconds", "lifecycle_busy", 1618},
		{"invalid arguments: --profile must be secure_client or standalone", "invalid_arguments", 1639},
		{"powershell7_required: the standalone enterprise lifecycle requires PowerShell 7", "powershell7_required", 1603},
		{"profile_conflict: a Cisco Secure Client DefenseClaw deployment exists", "profile_conflict", 1603},
		{"Install requires -Config", "lifecycle_error", 1603},
	} {
		result := enterprisestatus.New("install", "standalone", "windows", "1.4.0")
		result.AddError(windowsEnterpriseMessageCode(tc.message, "lifecycle_error"), tc.message)
		if result.Errors[0].Code != tc.code {
			t.Fatalf("%q classified %q, want %q", tc.message, result.Errors[0].Code, tc.code)
		}
		if got := result.Finish("windows", windowsEnterpriseFailureCodeFor(result)); got != tc.exit {
			t.Fatalf("%q exit %d, want %d", tc.message, got, tc.exit)
		}
	}
}

func TestWindowsEnterpriseStandaloneUninstallOnCleanHostIsNoop(t *testing.T) {
	originalFootprint := windowsEnterpriseStandaloneFootprint
	originalRunner := windowsEnterpriseStandaloneRunner
	originalObserver := windowsEnterpriseStandaloneObserver
	t.Cleanup(func() {
		windowsEnterpriseStandaloneFootprint = originalFootprint
		windowsEnterpriseStandaloneRunner = originalRunner
		windowsEnterpriseStandaloneObserver = originalObserver
	})
	windowsEnterpriseStandaloneFootprint = func() (bool, error) { return false, nil }
	windowsEnterpriseStandaloneRunner = func(context.Context, *cobra.Command, string, []string) (windowsEnterpriseStandaloneRun, error) {
		return windowsEnterpriseStandaloneRun{}, errors.New("installer must not run on a clean host")
	}
	windowsEnterpriseStandaloneObserver = func(*enterprisestatus.Result, *windowsEnterpriseLifecycleOptions) string { return "" }
	command := &cobra.Command{}
	var stdout bytes.Buffer
	command.SetOut(&stdout)
	opts := &windowsEnterpriseLifecycleOptions{resolvedProfile: "standalone", jsonOutput: true}
	if err := runWindowsEnterpriseStandaloneAction(context.Background(), command, "uninstall", opts, `C:\x\install-enterprise.ps1`, nil); err != nil {
		t.Fatal(err)
	}
	var result enterprisestatus.Result
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.OK || !result.Noop || result.NoopReason != "not_installed" {
		t.Fatalf("result %+v", result)
	}
}

func TestWindowsEnterpriseEventMapping(t *testing.T) {
	for _, tc := range []struct {
		action string
		ok     bool
		noop   bool
		code   string
		id     uint32
		logged bool
	}{
		{action: "install", ok: true, id: 100, logged: true},
		{action: "upgrade", ok: true, id: 101, logged: true},
		{action: "repair", ok: true, id: 102, logged: true},
		{action: "uninstall", ok: true, id: 110, logged: true},
		{action: "ensure", ok: true, noop: true, id: 111, logged: true},
		{action: "ensure", ok: true, id: 112, logged: true},
		{action: "status", ok: true, logged: false},
		{action: "verify", ok: false, code: "not_ready", id: 120, logged: true},
		{action: "install", ok: false, code: "lifecycle_error", id: 130, logged: true},
		{action: "ensure", ok: false, code: "lifecycle_busy", id: 140, logged: true},
		{action: "install", ok: false, code: "powershell7_required", id: 150, logged: true},
	} {
		result := enterprisestatus.New(tc.action, "standalone", "windows", "1.4.0")
		result.Noop = tc.noop
		if tc.code != "" {
			result.AddError(tc.code, "x")
		}
		result.Finish("windows", 0)
		id, _, logged := windowsEnterpriseEventFor(result)
		if logged != tc.logged || id != tc.id {
			t.Fatalf("%+v: got id %d logged %t", tc, id, logged)
		}
	}
}

func TestValidateWindowsEnterpriseStandaloneHostRefusesEmulation(t *testing.T) {
	original := windowsEnterpriseNativeMachine
	t.Cleanup(func() { windowsEnterpriseNativeMachine = original })
	windowsEnterpriseNativeMachine = func() (uint16, error) { return 0xAA64, nil } // IMAGE_FILE_MACHINE_ARM64
	if err := validateWindowsEnterpriseStandaloneHost(); err == nil || !strings.HasPrefix(err.Error(), "unsupported_architecture:") {
		t.Fatalf("ARM64 host: %v", err)
	}
	windowsEnterpriseNativeMachine = func() (uint16, error) { return windowsImageFileMachineAMD64, nil }
	if err := validateWindowsEnterpriseStandaloneHost(); err != nil {
		t.Fatalf("x64 host: %v", err)
	}
}

func TestWindowsEnterpriseStderrCodeKeepsInstallerRefusals(t *testing.T) {
	for body, want := range map[string]string{
		"powershell7_required: the standalone enterprise lifecycle requires PowerShell 7\r\nAt line:1":    "powershell7_required: the standalone enterprise lifecycle requires PowerShell 7",
		"Exception: powershell_32bit_host: run the standalone enterprise lifecycle from a 64-bit process": "powershell_32bit_host: run the standalone enterprise lifecycle from a 64-bit process",
		"powershell_constrained_language: the standalone enterprise lifecycle compiles":                   "powershell_constrained_language: the standalone enterprise lifecycle compiles",
		"unrelated failure": "",
	} {
		if got := windowsEnterpriseStderrCode([]byte(body)); got != want {
			t.Fatalf("stderr %q: got %q, want %q", body, got, want)
		}
	}
	result := enterprisestatus.New("install", "standalone", "windows", "1.4.0")
	result.AddError(windowsEnterpriseMessageCode("powershell_constrained_language: requires FullLanguage (exit status 1)", "x"), "m")
	if result.Errors[0].Code != "powershell_constrained_language" {
		t.Fatalf("code %q", result.Errors[0].Code)
	}
}

func TestWindowsEnterpriseStandalonePreflightFailureIsSchemaTwo(t *testing.T) {
	originalObserver := windowsEnterpriseStandaloneObserver
	t.Cleanup(func() { windowsEnterpriseStandaloneObserver = originalObserver })
	windowsEnterpriseStandaloneObserver = func(*enterprisestatus.Result, *windowsEnterpriseLifecycleOptions) string { return "" }
	for _, tc := range []struct {
		cause error
		code  string
		exit  int
	}{
		{windowsEnterpriseInvalidArguments("--trust-mode must be authenticode or hash_pinned"), "invalid_arguments", 1639},
		{errors.Join(errPowerShell7Required, errors.New("not registered")), "powershell7_required", 1603},
		{errors.New("profile_conflict: this host carries a secure_client enterprise deployment"), "profile_conflict", 1603},
	} {
		command := &cobra.Command{}
		var stdout bytes.Buffer
		command.SetOut(&stdout)
		err := writeWindowsEnterpriseStandalonePreflightFailure(command, "install", &windowsEnterpriseLifecycleOptions{jsonOutput: true}, tc.cause)
		if got := commandExitCode(err); got != tc.exit {
			t.Fatalf("%v: exit %d, want %d", tc.cause, got, tc.exit)
		}
		var result enterprisestatus.Result
		if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.SchemaVersion != 2 || result.OK || len(result.Errors) != 1 || result.Errors[0].Code != tc.code || result.ExitCode != tc.exit {
			t.Fatalf("%v: result %+v", tc.cause, result)
		}
	}
}

func TestWindowsEnterpriseLifecycleLogRotatesFiveGenerations(t *testing.T) {
	directory := t.TempDir()
	originalLimit := windowsEnterpriseLogLimit
	t.Cleanup(func() { windowsEnterpriseLogLimit = originalLimit })
	windowsEnterpriseLogLimit = 600
	for run := 0; run < 40; run++ {
		result := enterprisestatus.New("status", "standalone", "windows", "1.4.0")
		result.Finish("windows", 0)
		path, err := writeWindowsEnterpriseLifecycleLog(directory, result)
		if err != nil {
			t.Fatal(err)
		}
		if path != filepath.Join(directory, windowsEnterpriseLogName) || result.LogPath != path {
			t.Fatalf("log path %q / %q", path, result.LogPath)
		}
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	want := []string{
		windowsEnterpriseLogName, windowsEnterpriseLogName + ".1", windowsEnterpriseLogName + ".2",
		windowsEnterpriseLogName + ".3", windowsEnterpriseLogName + ".4", windowsEnterpriseLastResult,
	}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("log files %q, want %q", names, want)
	}
	body, err := os.ReadFile(filepath.Join(directory, windowsEnterpriseLastResult))
	if err != nil {
		t.Fatal(err)
	}
	var last enterprisestatus.Result
	if err := json.Unmarshal(body, &last); err != nil || last.SchemaVersion != 2 || last.Action != "status" {
		t.Fatalf("last result %q: %v", body, err)
	}
}

func TestWindowsEnterpriseRecoveredFailedInstallIsRecognizedOnlyAlone(t *testing.T) {
	recovered := &windowsEnterpriseInstallerReport{
		Error: "Uninstall recovered a failed initial install; run Install to create a deployment",
	}
	if !windowsEnterpriseRecoveredFailedInstall(recovered) {
		t.Fatal("the rolled-back first install was not recognized")
	}
	for name, report := range map[string]*windowsEnterpriseInstallerReport{
		"ok":        {OK: true},
		"installed": {Installed: true, Error: recovered.Error},
		"pending":   {TransactionPending: true, Error: recovered.Error},
		"other":     {Errors: []string{recovered.Error, "service DefenseClawGateway failed to stop"}},
		"empty":     {},
	} {
		if windowsEnterpriseRecoveredFailedInstall(report) {
			t.Fatalf("%s report was treated as a recovered first install", name)
		}
	}
}
