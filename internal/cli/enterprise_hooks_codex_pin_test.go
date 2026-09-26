// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

type codexPinStubCalls struct {
	ensure, remove, inspect int
	removeErr               error
}

func stubEnterpriseHookCodexPin(t *testing.T, supported bool, inspectState string, ensureErr error) *codexPinStubCalls {
	t.Helper()
	calls := &codexPinStubCalls{}
	originalSupported := enterpriseHookCodexPinSupported
	originalEnsure := enterpriseHookCodexPinEnsure
	originalRemove := enterpriseHookCodexPinRemove
	originalInspect := enterpriseHookCodexPinInspect
	originalCfg := cfg
	t.Cleanup(func() {
		enterpriseHookCodexPinSupported = originalSupported
		enterpriseHookCodexPinEnsure = originalEnsure
		enterpriseHookCodexPinRemove = originalRemove
		enterpriseHookCodexPinInspect = originalInspect
		cfg = originalCfg
	})
	enterpriseHookCodexPinSupported = func() bool { return supported }
	enterpriseHookCodexPinEnsure = func() (enterprisehooks.CodexRequirementsPinResult, error) {
		calls.ensure++
		return enterprisehooks.CodexRequirementsPinResult{State: enterprisehooks.CodexRequirementsPinOwned}, ensureErr
	}
	enterpriseHookCodexPinRemove = func() (enterprisehooks.CodexRequirementsPinResult, error) {
		calls.remove++
		return enterprisehooks.CodexRequirementsPinResult{State: enterprisehooks.CodexRequirementsPinAbsent}, calls.removeErr
	}
	enterpriseHookCodexPinInspect = func() (enterprisehooks.CodexRequirementsPinResult, error) {
		calls.inspect++
		return enterprisehooks.CodexRequirementsPinResult{Path: "/private/etc/codex/requirements.toml", State: inspectState}, nil
	}
	cfg = &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	return calls
}

func codexPinManifest(targets ...enterprisehooks.ManifestTarget) enterprisehooks.Manifest {
	return enterprisehooks.Manifest{Version: 1, Targets: targets}
}

func TestReconcileEnterpriseHookCodexPinFollowsEnabledCodexTargets(t *testing.T) {
	disabled := false
	codex := enterprisehooks.ManifestTarget{User: "alice", Connector: "codex"}
	claude := enterprisehooks.ManifestTarget{User: "alice", Connector: "claudecode"}
	disabledCodex := enterprisehooks.ManifestTarget{User: "bob", Connector: "codex", Enabled: &disabled}

	calls := stubEnterpriseHookCodexPin(t, true, enterprisehooks.CodexRequirementsPinOwned, nil)
	if warning, err := reconcileEnterpriseHookCodexPin(codexPinManifest(claude, codex)); err != nil || warning != "" ||
		calls.ensure != 1 || calls.remove != 0 {
		t.Fatalf("codex target: warning=%q err=%v calls=%+v, want one ensure", warning, err, calls)
	}
	if warning, err := reconcileEnterpriseHookCodexPin(codexPinManifest(claude, disabledCodex)); err != nil || warning != "" ||
		calls.remove != 1 {
		t.Fatalf("no enabled codex target: warning=%q err=%v calls=%+v, want the owned pin retired", warning, err, calls)
	}

	cfg = &config.Config{}
	if _, err := reconcileEnterpriseHookCodexPin(codexPinManifest(codex)); err != nil || calls.ensure != 1 || calls.remove != 1 {
		t.Fatalf("unmanaged deployment touched the machine pin: err=%v calls=%+v", err, calls)
	}

	calls = stubEnterpriseHookCodexPin(t, false, enterprisehooks.CodexRequirementsPinOwned, nil)
	if _, err := reconcileEnterpriseHookCodexPin(codexPinManifest(codex)); err != nil || calls.ensure != 0 || calls.remove != 0 {
		t.Fatalf("unsupported platform touched the machine pin: err=%v calls=%+v", err, calls)
	}
}

// Publishing failures fail the Codex targets; a failure to retire a leftover
// pin, which only keeps hooks enabled, is reported as a warning.
func TestReconcileEnterpriseHookCodexPinRowsReportsFailures(t *testing.T) {
	codex := enterprisehooks.ManifestTarget{User: "alice", Connector: "codex"}
	failure := errors.New("requirements are not editable")
	stubEnterpriseHookCodexPin(t, true, enterprisehooks.CodexRequirementsPinAbsent, failure)
	rows := []enterpriseHookReconcileRow{
		{User: "alice", Connector: "codex", OK: true},
		{User: "alice", Connector: "claudecode", OK: true},
	}
	failures := 0
	warnings := reconcileEnterpriseHookCodexPinOutcome(codexPinManifest(codex)).applyToRows(rows, &failures)
	if failures != 1 || rows[0].OK || !strings.Contains(rows[0].Error, failure.Error()) || !rows[1].OK || len(warnings) != 0 {
		t.Fatalf("publish failure: failures=%d rows=%+v warnings=%v", failures, rows, warnings)
	}

	failedRows := []enterpriseHookReconcileRow{{User: "alice", Connector: "codex", Error: "setup failed"}}
	failures = 1
	warnings = reconcileEnterpriseHookCodexPinOutcome(codexPinManifest(codex)).applyToRows(failedRows, &failures)
	if failures != 1 || len(warnings) != 1 || !strings.Contains(warnings[0], failure.Error()) {
		t.Fatalf("publish failure without a successful codex row: failures=%d warnings=%v", failures, warnings)
	}

	calls := stubEnterpriseHookCodexPin(t, true, enterprisehooks.CodexRequirementsPinAbsent, nil)
	calls.removeErr = errors.New("requirements are writable by group")
	claudeRows := []enterpriseHookReconcileRow{{User: "alice", Connector: "claudecode", OK: true}}
	failures = 0
	warnings = reconcileEnterpriseHookCodexPinOutcome(
		codexPinManifest(enterprisehooks.ManifestTarget{User: "alice", Connector: "claudecode"}),
	).applyToRows(claudeRows, &failures)
	if failures != 0 || !claudeRows[0].OK || len(warnings) != 1 || !strings.Contains(warnings[0], "retire") {
		t.Fatalf("retire failure: failures=%d rows=%+v warnings=%v", failures, claudeRows, warnings)
	}
}

// A Codex target is reported protected only while the machine requirements
// keep Codex hooks on.
func TestEnterpriseHookCodexPinFailsCodexRowsWhenThePinIsMissing(t *testing.T) {
	codex := enterprisehooks.ManifestTarget{User: "alice", Connector: "codex"}
	stubEnterpriseHookCodexPin(t, true, enterprisehooks.CodexRequirementsPinAbsent, nil)
	pinErr := verifyEnterpriseHookCodexPin(codexPinManifest(codex))
	if pinErr == nil || !strings.Contains(pinErr.Error(), "[features] hooks = true") {
		t.Fatalf("verify without a pin = %v", pinErr)
	}
	rows := []enterpriseHookReconcileRow{
		{User: "alice", Connector: "codex", OK: true, Result: &enterprisehooks.InstallResult{Connector: "codex"}},
		{User: "alice", Connector: "claudecode", OK: true},
		{User: "bob", Connector: "codex", Pending: true},
		{User: "carol", Connector: "codex", Error: "earlier failure"},
	}
	if failed := markEnterpriseHookCodexPinRows(rows, pinErr); failed != 1 {
		t.Fatalf("failed rows = %d, want only the successful codex row", failed)
	}
	if rows[0].OK || rows[0].Result != nil || rows[0].Error != pinErr.Error() {
		t.Fatalf("codex row after a missing pin = %+v", rows[0])
	}
	if !rows[1].OK || !rows[2].Pending || rows[3].Error != "earlier failure" {
		t.Fatalf("unrelated rows changed: %+v", rows[1:])
	}
	if failed := markEnterpriseHookCodexPinRows(rows, nil); failed != 0 {
		t.Fatalf("nil pin error failed %d rows", failed)
	}

	for _, state := range []string{enterprisehooks.CodexRequirementsPinOwned, enterprisehooks.CodexRequirementsPinAdministrator} {
		stubEnterpriseHookCodexPin(t, true, state, nil)
		if err := verifyEnterpriseHookCodexPin(codexPinManifest(codex)); err != nil {
			t.Fatalf("verify with a %s pin = %v", state, err)
		}
	}
	calls := stubEnterpriseHookCodexPin(t, true, enterprisehooks.CodexRequirementsPinAbsent, nil)
	if err := verifyEnterpriseHookCodexPin(codexPinManifest(enterprisehooks.ManifestTarget{Connector: "claudecode"})); err != nil || calls.inspect != 0 {
		t.Fatalf("verify without codex targets = %v (inspect calls %d)", err, calls.inspect)
	}
}

// The macOS uninstaller calls remove on hosts whose config may be gone.
func TestEnterpriseHooksCodexPinCommandSkipsDaemonBootstrap(t *testing.T) {
	command, _, err := rootCmd.Find([]string{"enterprise", "hooks", "codex-requirements-pin", "remove"})
	if err != nil || command == nil || command.Name() != "remove" {
		t.Fatalf("remove command = %v, %v", command, err)
	}
	if command.Annotations["defenseclaw.skip-daemon-bootstrap"] != "true" || !command.Parent().Hidden {
		t.Fatalf("remove command annotations=%v hidden=%t", command.Annotations, command.Parent().Hidden)
	}
	for _, action := range []string{"status", "ensure"} {
		if found, _, err := rootCmd.Find([]string{"enterprise", "hooks", "codex-requirements-pin", action}); err != nil || found.Name() != action {
			t.Fatalf("%s command = %v, %v", action, found, err)
		}
	}
}
