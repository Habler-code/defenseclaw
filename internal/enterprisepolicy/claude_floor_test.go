// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const wantClaudeFloorBytes = "{\n  \"requiredMinimumVersion\": \"2.1.154\"\n}\n"

func claudeFloorFile(t *testing.T, opts Options) string {
	t.Helper()
	path, err := ClaudeVersionFloorPath(opts)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func fileExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func hasDetail(state State, substring string) bool {
	for _, detail := range state.Details {
		if strings.Contains(detail, substring) {
			return true
		}
	}
	return false
}

func floorConflicts(state State) []string {
	var out []string
	for _, conflict := range state.Conflicts {
		if strings.Contains(conflict, "version floor") {
			out = append(out, conflict)
		}
	}
	return out
}

func reconcileClaude(t *testing.T, opts Options) State {
	t.Helper()
	state, err := claudeTarget{}.Reconcile(opts)
	if err != nil {
		t.Fatal(err)
	}
	return state
}

func TestClaudeVersionFloorIsTheLowestVerifiedHookContract(t *testing.T) {
	floor := ClaudeVersionFloor()
	if floor != "2.1.154" {
		t.Fatalf("Claude Code version floor = %q, want 2.1.154 (claudecode-hooks-v1)", floor)
	}
	for _, contract := range connector.KnownHookContracts("claudecode") {
		if contract.MinAgentVersion != "" && compareVersions(contract.MinAgentVersion, floor) < 0 {
			t.Fatalf("contract %s starts at %s, below the floor %s", contract.ContractID, contract.MinAgentVersion, floor)
		}
	}
}

// The floor is its own drop-in: the hook drop-in keeps its exact bytes and
// never carries requiredMinimumVersion.
func TestClaudeVersionFloorWrittenWhenNoSourceSetsIt(t *testing.T) {
	withHigherSources(t)
	opts := testOptions(t)
	adminSettings := `{"permissions": {"deny": ["Bash(rm -rf /)"]}}` + "\n"
	base := filepath.Join(claudeDir(t, opts), "managed-settings.json")
	writeFile(t, base, adminSettings)

	state := reconcileClaude(t, opts)
	mustNoConflicts(t, state)
	if got := readFile(t, claudeFloorFile(t, opts)); got != wantClaudeFloorBytes {
		t.Fatalf("floor drop-in = %q, want %q", got, wantClaudeFloorBytes)
	}
	if filepath.Base(claudeFloorFile(t, opts)) != "00-defenseclaw-version-floor.json" {
		t.Fatalf("floor drop-in name = %s", claudeFloorFile(t, opts))
	}
	hooks, err := renderClaudeDropIn(opts, opts.PolicyFor("claudecode"))
	if err != nil {
		t.Fatal(err)
	}
	dropIn := readFile(t, filepath.Join(claudeDir(t, opts), "managed-settings.d", DefenseClawDropInName))
	if dropIn != string(hooks) || strings.Contains(dropIn, "requiredMinimumVersion") {
		t.Fatalf("the hook drop-in must stay the unchanged hook rendering:\n%s", dropIn)
	}
	if readFile(t, base) != adminSettings {
		t.Fatal("administrator managed-settings.json changed")
	}
	floor := state.VersionFloor
	if floor == nil || floor.Owner != VersionFloorOwnerDefenseClaw || floor.Value != "2.1.154" || floor.Mode != "enforce" || floor.Source != claudeFloorFile(t, opts) {
		t.Fatalf("floor state: %+v", floor)
	}
	if !strings.Contains(floor.Summary(), "set by DefenseClaw") {
		t.Fatalf("summary: %s", floor.Summary())
	}
	if again := reconcileClaude(t, opts); again.Changed {
		t.Fatalf("a second reconcile must be a no-op: %+v", again)
	}
	if recorded, err := ClaudeVersionFloorRecorded(opts); err != nil || !recorded {
		t.Fatalf("floor ownership record: %v %v", recorded, err)
	}
}

// An administrator value in the base file, any drop-in (one sorting before
// DefenseClaw's included) or a higher-precedence source is kept byte for
// byte, DefenseClaw withdraws its own drop-in at the next reconcile, and the
// floor returns when the administrator removes the key.
func TestClaudeVersionFloorKeepsAnAdministratorValue(t *testing.T) {
	cases := []struct {
		name   string
		file   string
		higher bool
	}{
		{name: "base file", file: "managed-settings.json"},
		{name: "later drop-in", file: "managed-settings.d/10-company.json"},
		{name: "earlier drop-in", file: "managed-settings.d/000-company.json"},
		{name: "higher-precedence source", higher: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withHigherSources(t)
			opts := testOptions(t)
			reconcileClaude(t, opts)
			if !fileExists(claudeFloorFile(t, opts)) {
				t.Fatal("floor not written before the administrator sets the key")
			}
			admin := `{"requiredMinimumVersion": "2.1.200", "env": {"COMPANY": "1"}}` + "\n"
			source := `HKLM\SOFTWARE\Policies\ClaudeCode\Settings`
			if tc.higher {
				withHigherSources(t, higherSource(t, source, `{"requiredMinimumVersion": "2.1.200", "managedSourcesBehavior": "merge"}`))
			} else {
				source = path.Join(claudeDir(t, opts), tc.file)
				writeFile(t, source, admin)
			}
			state := reconcileClaude(t, opts)
			if conflicts := floorConflicts(state); len(conflicts) != 0 {
				t.Fatalf("an administrator value is not a conflict: %v", conflicts)
			}
			if fileExists(claudeFloorFile(t, opts)) {
				t.Fatal("DefenseClaw's floor must be withdrawn once an administrator source sets the key")
			}
			if recorded, _ := ClaudeVersionFloorRecorded(opts); recorded {
				t.Fatal("the floor record must go with the drop-in")
			}
			if !tc.higher && readFile(t, source) != admin {
				t.Fatal("the administrator's file must be untouched")
			}
			floor := state.VersionFloor
			if floor == nil || floor.Owner != VersionFloorOwnerAdministrator || floor.Source != source || floor.Value != "2.1.200" || floor.BelowFloor || floor.Invalid {
				t.Fatalf("floor state: %+v", floor)
			}
			if !hasDetail(state, "keeps the administrator's value") {
				t.Fatalf("the administrator value must be reported: %v", state.Details)
			}
			if verify, err := (claudeTarget{}).Verify(opts); err != nil || len(floorConflicts(verify)) != 0 || verify.VersionFloor.Owner != VersionFloorOwnerAdministrator {
				t.Fatalf("verify: %v %+v", err, verify)
			}

			if tc.higher {
				withHigherSources(t, higherSource(t, source, `{"managedSourcesBehavior": "merge"}`))
			} else if err := os.Remove(source); err != nil {
				t.Fatal(err)
			}
			reconcileClaude(t, opts)
			if readFile(t, claudeFloorFile(t, opts)) != wantClaudeFloorBytes {
				t.Fatal("the floor must come back when no administrator source sets the key")
			}
		})
	}
}

func TestClaudeVersionFloorReportsBelowFloorAndInvalidValues(t *testing.T) {
	for _, tc := range []struct {
		value   string
		below   bool
		invalid bool
		note    string
	}{
		{value: `"2.1.100"`, below: true, note: "below 2.1.154"},
		{value: `"latest"`, invalid: true, note: "not a major.minor.patch version"},
		{value: `5`, invalid: true, note: "not a major.minor.patch version"},
		{value: `"3.0.0"`, note: "keeps the administrator's value"},
	} {
		t.Run(tc.value, func(t *testing.T) {
			withHigherSources(t)
			opts := testOptions(t)
			writeFile(t, filepath.Join(claudeDir(t, opts), "managed-settings.json"), `{"requiredMinimumVersion": `+tc.value+`}`)
			state := reconcileClaude(t, opts)
			floor := state.VersionFloor
			if floor == nil || floor.Owner != VersionFloorOwnerAdministrator || floor.BelowFloor != tc.below || floor.Invalid != tc.invalid {
				t.Fatalf("floor state: %+v", floor)
			}
			if !hasDetail(state, tc.note) || len(floorConflicts(state)) != 0 {
				t.Fatalf("details %v conflicts %v", state.Details, state.Conflicts)
			}
			if fileExists(claudeFloorFile(t, opts)) {
				t.Fatal("an administrator value, even a low or invalid one, is never overridden")
			}
		})
	}
}

func TestClaudeVersionFloorModes(t *testing.T) {
	withHigherSources(t)

	report := testOptions(t)
	report.ClaudeVersionFloor = config.ClaudeVersionFloorReport
	state := reconcileClaude(t, report)
	if fileExists(claudeFloorFile(t, report)) || len(floorConflicts(state)) != 0 || !hasDetail(state, "version_floor: report") {
		t.Fatalf("report must only report: %+v", state)
	}

	off := testOptions(t)
	off.ClaudeVersionFloor = config.ClaudeVersionFloorOff
	state = reconcileClaude(t, off)
	if fileExists(claudeFloorFile(t, off)) || len(floorConflicts(state)) != 0 || state.VersionFloor.Mode != "off" {
		t.Fatalf("off must not write: %+v", state)
	}

	// Moving from enforce to report or off withdraws DefenseClaw's floor.
	opts := testOptions(t)
	reconcileClaude(t, opts)
	opts.ClaudeVersionFloor = config.ClaudeVersionFloorReport
	if state = reconcileClaude(t, opts); fileExists(claudeFloorFile(t, opts)) || !state.Changed {
		t.Fatalf("report must withdraw the floor: %+v", state)
	}

	// verify_only never writes; a missing floor is then advice, not a conflict.
	verifyOnly := withPolicy(testOptions(t), "claudecode", func(p *config.EnterpriseConnectorPolicy) { p.Ownership = "verify_only" })
	state = reconcileClaude(t, verifyOnly)
	if fileExists(claudeFloorFile(t, verifyOnly)) || len(floorConflicts(state)) != 0 || !hasDetail(state, "--format version-floor") {
		t.Fatalf("verify_only: %+v", state)
	}

	// Under enforce a missing floor fails verification.
	enforce := testOptions(t)
	reconcileClaude(t, enforce)
	if err := os.Remove(claudeFloorFile(t, enforce)); err != nil {
		t.Fatal(err)
	}
	verify, err := claudeTarget{}.Verify(enforce)
	if err != nil || len(floorConflicts(verify)) != 1 || verify.Covered {
		t.Fatalf("a missing floor must be a conflict: %v %+v", err, verify.Conflicts)
	}
	if verify.OwnedEntries == 0 {
		t.Fatal("a missing floor must not hide the published hooks")
	}
}

// Removal restores the preimage of a file that held other content under the
// floor name, and deletes a floor DefenseClaw wrote from nothing.
func TestClaudeVersionFloorRemovalRestoresThePreimage(t *testing.T) {
	withHigherSources(t)
	opts := testOptions(t)
	preimage := `{"env": {"COMPANY": "1"}}` + "\n"
	writeFile(t, claudeFloorFile(t, opts), preimage)
	state := reconcileClaude(t, opts)
	if readFile(t, claudeFloorFile(t, opts)) != wantClaudeFloorBytes || !hasDetail(state, "kept as the preimage") {
		t.Fatalf("the floor must replace unrelated content under its own name: %v", state.Details)
	}
	if _, err := (claudeTarget{}).RemoveOwned(opts); err != nil {
		t.Fatal(err)
	}
	if readFile(t, claudeFloorFile(t, opts)) != preimage {
		t.Fatal("removal must restore the preimage byte for byte")
	}
	if recorded, _ := ClaudeVersionFloorRecorded(opts); recorded {
		t.Fatal("removal must delete the floor record")
	}

	fresh := testOptions(t)
	reconcileClaude(t, fresh)
	if _, err := (claudeTarget{}).RemoveOwned(fresh); err != nil {
		t.Fatal(err)
	}
	if fileExists(claudeFloorFile(t, fresh)) {
		t.Fatal("removal must delete a floor DefenseClaw wrote")
	}
	if fileExists(filepath.Join(claudeDir(t, fresh), "managed-settings.d")) {
		t.Fatal("removal must also remove the drop-in directory DefenseClaw created")
	}
}

// A floor drop-in without a record is the administrator's (for example the
// version-floor export deployed under verify_only): removal leaves it.
func TestClaudeVersionFloorRemovalLeavesAnUnrecordedFile(t *testing.T) {
	withHigherSources(t)
	opts := testOptions(t)
	writeFile(t, claudeFloorFile(t, opts), wantClaudeFloorBytes)
	if _, err := (claudeTarget{}).RemoveOwned(opts); err != nil {
		t.Fatal(err)
	}
	if readFile(t, claudeFloorFile(t, opts)) != wantClaudeFloorBytes {
		t.Fatal("an unrecorded floor drop-in must stay")
	}
}

// A drop-in in DefenseClaw's exact rendering is DefenseClaw's even without a
// record (an earlier release's lower floor, or a write whose record a crash
// lost): reconcile updates and records it instead of reporting it as the
// administrator's.
func TestClaudeVersionFloorAdoptsItsOwnRendering(t *testing.T) {
	withHigherSources(t)
	opts := testOptions(t)
	writeFile(t, claudeFloorFile(t, opts), "{\n  \"requiredMinimumVersion\": \"2.1.100\"\n}\n")
	state := reconcileClaude(t, opts)
	if readFile(t, claudeFloorFile(t, opts)) != wantClaudeFloorBytes || state.VersionFloor.Owner != VersionFloorOwnerDefenseClaw {
		t.Fatalf("an older DefenseClaw floor must be raised: %+v", state.VersionFloor)
	}
	if _, err := (claudeTarget{}).RemoveOwned(opts); err != nil {
		t.Fatal(err)
	}
	if fileExists(claudeFloorFile(t, opts)) {
		t.Fatal("an adopted floor is removed at uninstall")
	}
}

func TestClaudeVersionFloorRetiredWithClaude(t *testing.T) {
	withHigherSources(t)
	opts := publishTestOptions(t)
	if _, err := Publish(opts, []string{"claudecode", "codex"}); err != nil {
		t.Fatal(err)
	}
	if !fileExists(claudeFloorFile(t, opts)) {
		t.Fatal("publish must write the floor")
	}
	result, err := Publish(opts, []string{"codex"})
	if err != nil {
		t.Fatal(err)
	}
	if fileExists(claudeFloorFile(t, opts)) || len(result.Retired) != 1 {
		t.Fatalf("disabling claudecode must withdraw the floor: %+v", result.Retired)
	}
	if recorded, _ := ClaudeVersionFloorRecorded(opts); recorded {
		t.Fatal("retire must delete the floor record")
	}
}

func TestClaudeVersionFloorOnDarwinAndItsPlist(t *testing.T) {
	withHigherSources(t)
	opts := testOptions(t)
	opts.GOOS = "darwin"
	reconcileClaude(t, opts)
	path := claudeFloorFile(t, opts)
	if !strings.HasSuffix(filepath.ToSlash(path), "/Library/Application Support/ClaudeCode/managed-settings.d/00-defenseclaw-version-floor.json") || readFile(t, path) != wantClaudeFloorBytes {
		t.Fatalf("darwin floor at %s", path)
	}
	plist := "/Library/Managed Preferences/com.anthropic.claudecode.plist"
	withHigherSources(t, higherSource(t, plist, `{"requiredMinimumVersion": "2.1.300"}`))
	state := reconcileClaude(t, opts)
	if fileExists(path) || state.VersionFloor.Owner != VersionFloorOwnerAdministrator || state.VersionFloor.Source != plist {
		t.Fatalf("a managed preferences value wins: %+v", state.VersionFloor)
	}
}

// A higher-precedence source without merge makes Claude Code ignore the
// files, so DefenseClaw's floor there does not apply: say so.
func TestClaudeVersionFloorNamesAReplacingSource(t *testing.T) {
	opts := testOptions(t)
	withHigherSources(t, higherSource(t, `HKLM\SOFTWARE\Policies\ClaudeCode\Settings`, `{"model": "opus"}`))
	state := reconcileClaude(t, opts)
	if !hasDetail(state, "outranks the managed settings files, so Claude Code ignores requiredMinimumVersion there") {
		t.Fatalf("details: %v", state.Details)
	}
}

func TestClaudeVersionFloorExport(t *testing.T) {
	opts := testOptions(t)
	data, err := claudeTarget{}.Export(opts, "version-floor")
	if err != nil || string(data) != wantClaudeFloorBytes {
		t.Fatalf("version-floor export: %v %q", err, data)
	}
	opts.ClaudeVersionFloor = config.ClaudeVersionFloorOff
	if _, err := (claudeTarget{}).Export(opts, "version-floor"); err == nil || !strings.Contains(err.Error(), "version_floor") {
		t.Fatalf("off must refuse the export, got %v", err)
	}
	hooks, err := claudeTarget{}.Export(testOptions(t), "json")
	if err != nil || strings.Contains(string(hooks), "requiredMinimumVersion") {
		t.Fatalf("the hook drop-in export must not carry the floor: %v", err)
	}
}

// The Windows pass runs inside the lifecycle's lock, only for the directory
// that lock guards, and takes no lock when there is nothing to do.
func TestClaudeVersionFloorLockedPass(t *testing.T) {
	withHigherSources(t)
	opts := testOptions(t)
	// The linux-rooted tree joins with "/" (also on a Windows host).
	dir := path.Dir(claudeFloorFile(t, opts))
	calls := 0
	locked := func(fn func(string) error) error {
		calls++
		return fn(dir)
	}
	var state State
	if err := reconcileClaudeVersionFloorFor(opts, []string{"codex"}, locked, &state); err != nil || calls != 0 {
		t.Fatalf("nothing to write or remove must take no lock: calls=%d %v", calls, err)
	}
	if err := reconcileClaudeVersionFloorFor(opts, []string{"claudecode"}, locked, &state); err != nil || calls != 1 {
		t.Fatalf("publish: calls=%d %v", calls, err)
	}
	if readFile(t, claudeFloorFile(t, opts)) != wantClaudeFloorBytes {
		t.Fatal("the locked pass must write the floor")
	}
	if fileExists(filepath.Join(dir, DefenseClawDropInName)) {
		t.Fatal("the locked pass must never write the hook drop-in")
	}
	wrong := func(fn func(string) error) error { return fn(filepath.Join(dir, "elsewhere")) }
	if err := os.Remove(claudeFloorFile(t, opts)); err != nil {
		t.Fatal(err)
	}
	if err := reconcileClaudeVersionFloorFor(opts, []string{"claudecode"}, wrong, &state); err == nil || fileExists(claudeFloorFile(t, opts)) {
		t.Fatalf("a lock for another directory must be refused: %v", err)
	}
	reconcileClaudeVersionFloorFor(opts, []string{"claudecode"}, locked, &state)
	if err := reconcileClaudeVersionFloorFor(opts, []string{"codex"}, locked, &state); err != nil || fileExists(claudeFloorFile(t, opts)) {
		t.Fatalf("an inactive claudecode must withdraw the floor: %v", err)
	}
	reconcileClaudeVersionFloorFor(opts, []string{"claudecode"}, locked, &state)
	failing := func(func(string) error) error { return errors.New("lock timeout") }
	if err := removeClaudeVersionFloorWith(opts, failing, &state); err == nil || !fileExists(claudeFloorFile(t, opts)) {
		t.Fatalf("removal must run inside the lock: %v", err)
	}
	if err := removeClaudeVersionFloorWith(opts, locked, &state); err != nil || fileExists(claudeFloorFile(t, opts)) {
		t.Fatalf("locked removal: %v", err)
	}
}

func TestStandaloneOptionsCarryTheVersionFloorMode(t *testing.T) {
	layout, err := managed.StandaloneLayoutFor("linux")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, Enterprise: config.EnterpriseConfig{Profile: managed.ProfileStandalone}}
	opts, err := StandaloneOptions(layout, "", "", cfg)
	if err != nil || opts.ClaudeVersionFloor != config.ClaudeVersionFloorEnforce {
		t.Fatalf("default mode: %q %v", opts.ClaudeVersionFloor, err)
	}
	cfg.Enterprise.MachinePolicy.ClaudeCode.VersionFloor = "Report"
	if opts, err = StandaloneOptions(layout, "", "", cfg); err != nil || opts.ClaudeVersionFloor != config.ClaudeVersionFloorReport {
		t.Fatalf("configured mode: %q %v", opts.ClaudeVersionFloor, err)
	}
}
