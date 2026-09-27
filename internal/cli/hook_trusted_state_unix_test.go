// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func withStandaloneHookRuntime(
	t *testing.T,
	goos string,
	load func(string) (*managed.RuntimeDescriptor, error),
	policy func(string) (enterprisepolicy.Options, bool),
	secureClientDir string,
) {
	t.Helper()
	oldGOOS, oldLoad, oldPolicy, oldSC := standaloneHookGOOS, standaloneRuntimeDescriptorLoad, standaloneMachinePolicyOptions, standaloneSecureClientInstallDir
	standaloneHookGOOS = goos
	standaloneRuntimeDescriptorLoad = load
	standaloneMachinePolicyOptions = policy
	standaloneSecureClientInstallDir = secureClientDir
	t.Cleanup(func() {
		standaloneHookGOOS, standaloneRuntimeDescriptorLoad, standaloneMachinePolicyOptions, standaloneSecureClientInstallDir = oldGOOS, oldLoad, oldPolicy, oldSC
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

func noMarkers(string) (enterprisepolicy.Options, bool) { return enterprisepolicy.Options{}, false }

// rootedMachinePolicy resolves the real standalone machine policy paths
// under root, as the publisher writes them.
func rootedMachinePolicy(root string) func(string) (enterprisepolicy.Options, bool) {
	return func(goos string) (enterprisepolicy.Options, bool) {
		layout, err := managed.StandaloneLayoutFor(goos)
		if err != nil {
			return enterprisepolicy.Options{}, false
		}
		opts := enterprisepolicy.LayoutOptions(layout, "", "")
		opts.Root = root
		opts.StateDir = filepath.Join(root, opts.StateDir)
		opts.PublicPolicyPath = filepath.Join(root, opts.PublicPolicyPath)
		opts.SkipTrustChecks = true
		return opts, true
	}
}

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
	markers := rootedMachinePolicy(dir)
	policyOpts, _ := markers("linux")
	claudeDir, _ := enterprisepolicy.ClaudeManagedDir(policyOpts)
	policy := filepath.Join(claudeDir, "managed-settings.d", enterprisepolicy.DefenseClawDropInName)
	if err := os.MkdirAll(filepath.Dir(policy), 0o755); err != nil {
		t.Fatal(err)
	}
	requirements, _ := enterprisepolicy.CodexRequirementsPath(policyOpts)
	if err := os.MkdirAll(filepath.Dir(requirements), 0o755); err != nil {
		t.Fatal(err)
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

// A descriptor that names no hook socket must fail closed: the standalone
// hook has no loopback TCP fallback and never reads a token.
func TestStandaloneHookRuntimeWithoutHookSocketFailsClosed(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			withStandaloneHookRuntime(t, goos,
				func(string) (*managed.RuntimeDescriptor, error) {
					descriptor := testDescriptor()
					descriptor.HookSocket = ""
					return descriptor, nil
				},
				noMarkers, "/nonexistent-secure-client")
			if enterpriseManagedHookRuntimeNoop("codex") {
				t.Fatal("a descriptor without a hook socket is never a no-op")
			}
			if reason := enterpriseManagedHookRuntimeFailureReason(); reason != standaloneRuntimeReasonHookSocketMissing {
				t.Fatalf("reason = %q, want %q", reason, standaloneRuntimeReasonHookSocketMissing)
			}
			if !enterpriseManagedHookRuntimeForceClosed() {
				t.Fatal("a descriptor without a hook socket must force the hook closed")
			}
			if _, _, _, ok := enterpriseManagedHookRuntimeConnection("codex"); ok {
				t.Fatal("a descriptor without a hook socket must not yield a TCP endpoint")
			}
			opts := buildHookOptionsForRuntime("codex", "PreToolUse", "", "", true)
			if opts.ManagedRuntimeFailure != standaloneRuntimeReasonHookSocketMissing || opts.ManagedStandalone || opts.ManagedUnixSocket != "" {
				t.Fatalf("fail-closed options wrong: failure=%q standalone=%v socket=%q",
					opts.ManagedRuntimeFailure, opts.ManagedStandalone, opts.ManagedUnixSocket)
			}
			if opts.FailMode != "closed" || !opts.StrictAvailability {
				t.Fatalf("hook must fail closed: fail=%q strict=%v", opts.FailMode, opts.StrictAvailability)
			}
		})
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
		opts, ok := defaultStandaloneMachinePolicyOptions(goos)
		if !ok {
			t.Fatalf("%s has no standalone layout", goos)
		}
		for _, connector := range []string{"codex", "claudecode", "cursor", "copilot", "opencode"} {
			target, ok := enterprisepolicy.TargetFor(connector)
			if !ok {
				t.Fatalf("%s has no machine policy target", connector)
			}
			if paths, err := target.Paths(opts); err != nil || len(paths) == 0 {
				t.Errorf("%s/%s has no machine-policy file: %v", goos, connector, err)
			}
		}
	}
	// Per-user-only connectors (Amp has no machine plugin path) never keep a
	// managed hook alive after uninstall.
	for _, connector := range []string{"antigravity", "amp"} {
		if _, ok := enterprisepolicy.TargetFor(connector); ok {
			t.Fatalf("per-user-only connector %s must not have a machine policy target", connector)
		}
	}
}

func TestStandaloneMachinePolicyPresenceUsesPublisherDetection(t *testing.T) {
	dir := t.TempDir()
	withStandaloneHookRuntime(t, "linux",
		func(string) (*managed.RuntimeDescriptor, error) { return nil, managed.ErrNoRuntimeDescriptor },
		rootedMachinePolicy(dir), filepath.Join(dir, "no-secure-client"))
	opts, _ := rootedMachinePolicy(dir)("linux")
	connectors := []string{"claudecode", "codex", "copilot", "cursor"}
	if _, err := enterprisepolicy.Publish(opts, connectors); err != nil {
		t.Fatal(err)
	}
	for _, connector := range connectors {
		if enterpriseManagedHookRuntimeNoop(connector) {
			t.Fatalf("%s: published machine policy without a descriptor must fail closed", connector)
		}
	}
	if _, err := enterprisepolicy.RemoveAll(opts); err != nil {
		t.Fatal(err)
	}
	for _, connector := range connectors {
		if !enterpriseManagedHookRuntimeNoop(connector) {
			t.Fatalf("%s: a clean uninstall must be a no-op (reason %q)", connector, enterpriseManagedHookRuntimeFailureReason())
		}
	}
}
