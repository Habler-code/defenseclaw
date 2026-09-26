// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func withStandaloneHookRuntime(
	t *testing.T,
	goos string,
	load func(string) (*managed.RuntimeDescriptor, error),
	markers func(string, string) []standaloneMachinePolicyMarker,
	secureClientDir string,
) {
	t.Helper()
	oldGOOS, oldLoad, oldMarkers, oldSC := standaloneHookGOOS, standaloneRuntimeDescriptorLoad, standaloneMachinePolicyMarkers, standaloneSecureClientInstallDir
	standaloneHookGOOS = goos
	standaloneRuntimeDescriptorLoad = load
	standaloneMachinePolicyMarkers = markers
	standaloneSecureClientInstallDir = secureClientDir
	t.Cleanup(func() {
		standaloneHookGOOS, standaloneRuntimeDescriptorLoad, standaloneMachinePolicyMarkers, standaloneSecureClientInstallDir = oldGOOS, oldLoad, oldMarkers, oldSC
		standaloneHookRuntime.Lock()
		standaloneHookRuntime.prepared = false
		standaloneHookRuntime.descriptor = nil
		standaloneHookRuntime.reason = ""
		standaloneHookRuntime.Unlock()
	})
}

func testDescriptor() *managed.RuntimeDescriptor {
	return &managed.RuntimeDescriptor{
		SchemaVersion:           managed.RuntimeDescriptorSchemaVersion,
		Profile:                 managed.ProfileStandalone,
		ServiceUser:             "defenseclaw",
		ServiceUID:              995,
		ServiceGID:              985,
		APIAddr:                 managed.StandaloneAPIAddr,
		HookSocket:              "/run/defenseclaw-hook/hook.sock",
		MachinePolicyConnectors: []string{"codex"},
	}
}

func noMarkers(string, string) []standaloneMachinePolicyMarker { return nil }

func TestStandaloneHookRuntimeUsesDescriptor(t *testing.T) {
	withStandaloneHookRuntime(t, "linux",
		func(string) (*managed.RuntimeDescriptor, error) { return testDescriptor(), nil },
		noMarkers, "/nonexistent-secure-client")
	t.Setenv("DEFENSECLAW_GATEWAY_ADDR", "10.0.0.1:1")
	t.Setenv("DEFENSECLAW_GATEWAY_TOKEN", "inherited")
	t.Setenv("DEFENSECLAW_FAIL_MODE", "open")
	t.Setenv("DEFENSECLAW_HOOK_MAX_BODY", "99999999")
	if enterpriseManagedHookRuntimeNoop("Codex") {
		t.Fatal("a present descriptor is never a no-op")
	}
	opts := buildHookOptionsForRuntime("codex", "PreToolUse", "", "", true)
	if opts.ManagedRuntimeFailure != "" {
		t.Fatalf("unexpected runtime failure %q", opts.ManagedRuntimeFailure)
	}
	if !opts.ManagedEnterprise || !opts.ManagedStandalone || opts.ManagedUnixSocket != "/run/defenseclaw-hook/hook.sock" || opts.ManagedServiceUID != 995 {
		t.Fatalf("standalone transport not bound to descriptor: %+v", opts)
	}
	if opts.APIAddr != managed.StandaloneAPIAddr {
		t.Fatalf("api addr = %q; environment must not redirect a managed hook", opts.APIAddr)
	}
	if opts.Token != "" || opts.FailMode != "closed" || !opts.StrictAvailability || opts.MaxBody != 1<<20 {
		t.Fatalf("inherited environment weakened the managed hook: token=%q fail=%q strict=%v max=%d",
			opts.Token, opts.FailMode, opts.StrictAvailability, opts.MaxBody)
	}
	layout, _ := managed.StandaloneLayoutFor("linux")
	if opts.Home != layout.ConfigDir {
		t.Fatalf("home = %q, want the administrator-owned %q", opts.Home, layout.ConfigDir)
	}
}

func TestStandaloneHookRuntimeNoopOnlyAfterUninstall(t *testing.T) {
	dir := t.TempDir()
	policy := filepath.Join(dir, "90-defenseclaw.json")
	markers := func(goos, connector string) []standaloneMachinePolicyMarker {
		if connector == "claudecode" {
			return []standaloneMachinePolicyMarker{{path: policy}}
		}
		if connector == "codex" {
			return []standaloneMachinePolicyMarker{{path: filepath.Join(dir, "requirements.toml"), needle: "defenseclaw-hook"}}
		}
		return nil
	}
	missing := func(string) (*managed.RuntimeDescriptor, error) { return nil, managed.ErrNoRuntimeDescriptor }
	withStandaloneHookRuntime(t, "linux", missing, markers, filepath.Join(dir, "no-secure-client"))

	if !enterpriseManagedHookRuntimeNoop("claudecode") {
		t.Fatal("descriptor and machine policy both absent must be a no-op")
	}
	if err := os.WriteFile(policy, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if enterpriseManagedHookRuntimeNoop("claudecode") {
		t.Fatal("machine policy without a descriptor must fail closed")
	}
	if reason := enterpriseManagedHookRuntimeFailureReason(); reason != standaloneRuntimeReasonDescriptorMissing {
		t.Fatalf("reason = %q", reason)
	}
	if !enterpriseManagedHookRuntimeForceClosed() {
		t.Fatal("missing descriptor with policy must force the hook closed")
	}
	opts := buildHookOptionsForRuntime("claudecode", "PreToolUse", "", "", true)
	if opts.ManagedRuntimeFailure != standaloneRuntimeReasonDescriptorMissing || opts.ManagedStandalone {
		t.Fatalf("fail-closed options wrong: %+v", opts)
	}

	requirements := filepath.Join(dir, "requirements.toml")
	if err := os.WriteFile(requirements, []byte("[hooks]\n# other admin hook\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !enterpriseManagedHookRuntimeNoop("codex") {
		t.Fatal("an admin requirements file without the DefenseClaw hook is not DefenseClaw policy")
	}
	if err := os.WriteFile(requirements, []byte("command = \"/opt/defenseclaw/bin/defenseclaw-hook hook --connector codex\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if enterpriseManagedHookRuntimeNoop("codex") {
		t.Fatal("requirements that still name defenseclaw-hook must fail closed")
	}
}

func TestStandaloneHookRuntimeUntrustedDescriptorFailsClosed(t *testing.T) {
	withStandaloneHookRuntime(t, "linux",
		func(string) (*managed.RuntimeDescriptor, error) {
			return nil, errors.New("owner uid 1000 is not trusted")
		},
		noMarkers, "/nonexistent-secure-client")
	if enterpriseManagedHookRuntimeNoop("codex") {
		t.Fatal("an untrusted descriptor must never be a no-op")
	}
	if reason := enterpriseManagedHookRuntimeFailureReason(); reason != standaloneRuntimeReasonInvalid {
		t.Fatalf("reason = %q", reason)
	}
	if _, _, _, ok := enterpriseManagedHookRuntimeConnection("codex"); ok {
		t.Fatal("an untrusted descriptor must not yield an endpoint")
	}
}

func TestStandaloneHookRuntimeKeepsSecureClientMacFailClosed(t *testing.T) {
	secureClient := t.TempDir()
	withStandaloneHookRuntime(t, "darwin",
		func(string) (*managed.RuntimeDescriptor, error) { return nil, managed.ErrNoRuntimeDescriptor },
		noMarkers, secureClient)
	if enterpriseManagedHookRuntimeNoop("claudecode") {
		t.Fatal("a Secure Client Mac keeps the historical fail-closed --enterprise-managed result")
	}
	if reason := enterpriseManagedHookRuntimeFailureReason(); reason != standaloneRuntimeReasonInvalid {
		t.Fatalf("reason = %q", reason)
	}
}

func TestStandaloneMachinePolicyMarkersCoverPublishedConnectors(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, connector := range []string{"codex", "claudecode", "cursor", "copilot", "opencode", "amp"} {
			if len(defaultStandaloneMachinePolicyMarkers(goos, connector)) == 0 {
				t.Errorf("%s/%s has no machine-policy marker", goos, connector)
			}
		}
	}
	if markers := defaultStandaloneMachinePolicyMarkers("linux", "antigravity"); markers != nil {
		t.Fatalf("per-user-only connector must not have machine-policy markers: %+v", markers)
	}
}
