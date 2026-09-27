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
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// Claude Code refuses to start when its version is below the managed
// requiredMinimumVersion. The check runs at each new session start (running
// sessions continue), an invalid value is ignored, and builds that predate
// the setting ignore it. The standalone profile sets it to the lowest Claude
// Code version with a verified DefenseClaw hook contract, so a build
// DefenseClaw cannot govern does not start.
//
// The floor lives in a drop-in of its own that holds nothing else, so the
// hook drop-in (90-defenseclaw.json, and the Windows lifecycle's rendering of
// it) never changes. DefenseClaw writes it only while no administrator source
// (managed-settings.json, another drop-in, HKLM Settings, the managed
// preferences plist) sets the key, and withdraws it at the next reconcile
// once one does: managed-settings.json merges before every drop-in, so
// leaving the floor in place would override an administrator value there.
// The name sorts first, so any administrator drop-in overrides it anyway.
const ClaudeVersionFloorDropInName = "00-defenseclaw-version-floor.json"

const (
	claudeVersionFloorKey = "requiredMinimumVersion"
	// claudeVersionFloorRecord names the floor drop-in's ownership record.
	claudeVersionFloorRecord = "claudecode-version-floor"
)

// Who sets Claude Code's requiredMinimumVersion.
const (
	VersionFloorOwnerDefenseClaw   = "defenseclaw"
	VersionFloorOwnerAdministrator = "administrator"
	VersionFloorOwnerNone          = "none"
)

// claudeVersionFloorShape matches DefenseClaw's rendering of the floor
// drop-in for any floor, so a drop-in an earlier release wrote with a lower
// floor, or one whose ownership record a crash lost, is still recognized.
var claudeVersionFloorShape = regexp.MustCompile(`^\{\n  "requiredMinimumVersion": "[0-9]+\.[0-9]+\.[0-9]+"\n\}\n$`)

// claudeVersionPattern is a major.minor.patch version, optionally with a
// pre-release or build suffix.
var claudeVersionPattern = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$`)

// VersionFloorState is Claude Code's requiredMinimumVersion as the
// claudecode machine policy report shows it.
type VersionFloorState struct {
	// Mode is enterprise.machine_policy.claudecode.version_floor.
	Mode string `json:"mode"`
	// Floor is the lowest Claude Code version with a verified hook contract.
	Floor string `json:"floor"`
	// Path is DefenseClaw's floor drop-in.
	Path string `json:"path"`
	// Owner says who sets requiredMinimumVersion (defenseclaw,
	// administrator or none).
	Owner string `json:"owner"`
	// Value and Source are the effective value and where it is set.
	Value  string `json:"value,omitempty"`
	Source string `json:"source,omitempty"`
	// BelowFloor marks an administrator value below Floor; Invalid one that
	// is not a version, which Claude Code ignores.
	BelowFloor bool `json:"below_floor,omitempty"`
	Invalid    bool `json:"invalid,omitempty"`
}

// Summary is the one-line form `enterprise policy show` prints.
func (s VersionFloorState) Summary() string {
	switch s.Owner {
	case VersionFloorOwnerDefenseClaw:
		return fmt.Sprintf("requiredMinimumVersion %s set by DefenseClaw (%s), version_floor=%s", s.Value, s.Source, s.Mode)
	case VersionFloorOwnerAdministrator:
		note := ""
		switch {
		case s.Invalid:
			note = "; not a version, so no floor applies"
		case s.BelowFloor:
			note = "; below DefenseClaw's floor " + s.Floor
		}
		return fmt.Sprintf("requiredMinimumVersion %s set by the administrator (%s%s), version_floor=%s", s.Value, s.Source, note, s.Mode)
	default:
		return fmt.Sprintf("requiredMinimumVersion not set (DefenseClaw's floor is %s), version_floor=%s", dashIfBlank(s.Floor), s.Mode)
	}
}

func dashIfBlank(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

// ClaudeVersionFloor is the lowest Claude Code version DefenseClaw has a
// verified hook contract for: the requiredMinimumVersion it sets. Empty when
// no contract has a lower bound.
func ClaudeVersionFloor() string {
	floor := ""
	for _, contract := range connector.KnownHookContracts(claudeConnector) {
		minimum := connector.NormalizeAgentVersion(claudeConnector, contract.MinAgentVersion)
		if minimum == "" {
			continue
		}
		if floor == "" || compareVersions(minimum, floor) < 0 {
			floor = minimum
		}
	}
	return floor
}

func (o Options) claudeVersionFloorMode() string {
	if mode := strings.ToLower(strings.TrimSpace(o.ClaudeVersionFloor)); mode != "" {
		return mode
	}
	return config.ClaudeVersionFloorEnforce
}

// ClaudeVersionFloorPath is DefenseClaw's Claude Code version floor drop-in.
func ClaudeVersionFloorPath(opts Options) (string, error) {
	dir, err := ClaudeManagedDir(opts)
	if err != nil {
		return "", err
	}
	return joinFor(opts, joinFor(opts, dir, "managed-settings.d"), ClaudeVersionFloorDropInName), nil
}

func renderClaudeVersionFloor(floor string) ([]byte, error) {
	doc := newObject()
	doc.set(claudeVersionFloorKey, floor)
	return encodeOrdered(doc)
}

// claudeVersionFloorStrip treats DefenseClaw's rendering as its whole file;
// any other content under the drop-in name is kept as the preimage.
func claudeVersionFloorStrip() stripFunc {
	return wholeFileStrip(claudeVersionFloorShape.Match)
}

// claudeFloorSetting is one administrator source that sets the key.
type claudeFloorSetting struct {
	source string
	value  any
	higher bool
}

// claudeFloorPlan is what DefenseClaw finds for the floor on disk.
type claudeFloorPlan struct {
	mode    string
	floor   string
	path    string
	current []byte
	exists  bool
	record  *ownershipRecord
	// owned: the drop-in at path is DefenseClaw's (its ownership record
	// names it, or it is exactly DefenseClaw's rendering).
	owned bool
	// admin is the effective administrator setting; nil when none sets it.
	admin *claudeFloorSetting
	// replacing names a higher-precedence source without
	// managedSourcesBehavior: merge, which makes Claude Code ignore the
	// managed settings files, the floor drop-in included.
	replacing string
}

func planClaudeVersionFloor(opts Options, sources []claudeSource, higher []higherClaudeSource) (claudeFloorPlan, error) {
	plan := claudeFloorPlan{mode: opts.claudeVersionFloorMode(), floor: ClaudeVersionFloor()}
	path, err := ClaudeVersionFloorPath(opts)
	if err != nil {
		return plan, err
	}
	plan.path = path
	if plan.current, plan.exists, err = readPolicyFile(opts, path); err != nil {
		return plan, err
	}
	if plan.record, err = loadRecord(opts, claudeVersionFloorRecord); err != nil {
		return plan, err
	}
	plan.owned = plan.exists && ((plan.record != nil && plan.record.Path == path) || claudeVersionFloorShape.Match(plan.current))
	for _, source := range sources {
		if plan.owned && source.name == path {
			continue
		}
		if value, ok := source.doc.get(claudeVersionFloorKey); ok && value != nil {
			plan.admin = &claudeFloorSetting{source: source.name, value: value}
		}
	}
	for _, source := range higher {
		if behavior, _ := source.doc.get("managedSourcesBehavior"); behavior != "merge" && plan.replacing == "" {
			plan.replacing = source.name
		}
		if value, ok := source.doc.get(claudeVersionFloorKey); ok && value != nil && (plan.admin == nil || !plan.admin.higher) {
			plan.admin = &claudeFloorSetting{source: source.name, value: value, higher: true}
		}
	}
	return plan, nil
}

// wanted reports whether DefenseClaw's floor drop-in should be in place.
func (p claudeFloorPlan) wanted(policy config.ResolvedConnectorPolicy) bool {
	return p.mode == config.ClaudeVersionFloorEnforce && p.floor != "" && p.admin == nil &&
		policy.Ownership == config.MachinePolicyOwnershipMerge
}

// applyClaudeVersionFloor writes DefenseClaw's floor drop-in when the plan
// wants it and withdraws it otherwise (verify_only never writes or removes).
// It runs on every reconcile, so an administrator who sets the key gets the
// drop-in withdrawn at the next cycle, and one who removes theirs gets the
// floor back.
func applyClaudeVersionFloor(opts Options, policy config.ResolvedConnectorPolicy, state *State) error {
	sources, err := readClaudeFileSources(opts)
	if err != nil {
		return err
	}
	// An unreadable higher-precedence source is reported by the inspection;
	// here it can only lead to a floor that source overrides anyway.
	higher, _ := claudeHigherSources(opts)
	plan, err := planClaudeVersionFloor(opts, sources, higher)
	if err != nil {
		return err
	}
	if plan.wanted(policy) {
		rendered, err := renderClaudeVersionFloor(plan.floor)
		if err != nil {
			return err
		}
		if plan.exists && !plan.owned {
			state.detail("%s held content DefenseClaw did not write; it is kept as the preimage and restored when DefenseClaw removes its floor", plan.path)
		}
		changed, err := publishWithRecord(opts, claudeVersionFloorRecord, plan.path, plan.current, plan.exists, rendered,
			plan.owned && bytes.Equal(plan.current, rendered), claudeVersionFloorStrip(), state)
		state.Changed = state.Changed || changed
		return err
	}
	if policy.Ownership == config.MachinePolicyOwnershipVerifyOnly {
		return nil
	}
	return withdrawClaudeVersionFloor(opts, plan, state)
}

// withdrawClaudeVersionFloor removes DefenseClaw's floor drop-in, restoring
// the recorded preimage when the file is what DefenseClaw last wrote.
func withdrawClaudeVersionFloor(opts Options, plan claudeFloorPlan, state *State) error {
	switch {
	case plan.record != nil:
		before := state.Changed
		state.Changed = false
		err := restoreOrStrip(opts, claudeVersionFloorRecord, plan.path, claudeVersionFloorStrip(), true, state)
		state.Changed = before || state.Changed
		return err
	case plan.owned:
		// DefenseClaw's exact rendering whose record a crash lost.
		if err := removePolicyFile(opts, plan.path); err != nil {
			return err
		}
		state.Changed = true
		state.detail("removed %s", plan.path)
	}
	return nil
}

// removeClaudeVersionFloor removes the floor drop-in DefenseClaw recorded
// writing (uninstall, retire). Without a record the file is the
// administrator's (for example the `version-floor` export deployed under
// verify_only) and stays.
func removeClaudeVersionFloor(opts Options, state *State) error {
	path, err := ClaudeVersionFloorPath(opts)
	if err != nil {
		return err
	}
	return restoreOrStrip(opts, claudeVersionFloorRecord, path, claudeVersionFloorStrip(), true, state)
}

// ClaudeVersionFloorRecorded reports whether DefenseClaw still records
// owning a Claude Code version floor drop-in; an uninstall must end with
// false.
func ClaudeVersionFloorRecorded(opts Options) (bool, error) {
	return recordExists(opts, claudeVersionFloorRecord)
}

func recordExists(opts Options, name string) (bool, error) {
	path, err := recordPath(opts, name)
	if err != nil {
		return false, err
	}
	if _, err := os.Lstat(path); err == nil {
		return true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	return false, nil
}

// claudeVersionFloorPresent reports whether a floor drop-in or its record
// exists, so a pass with nothing to write or remove takes no lock and
// creates no directory.
func claudeVersionFloorPresent(opts Options) (bool, error) {
	if recorded, err := recordExists(opts, claudeVersionFloorRecord); err != nil || recorded {
		return recorded, err
	}
	path, err := ClaudeVersionFloorPath(opts)
	if err != nil {
		return false, err
	}
	if _, err := os.Lstat(platformPath(opts, path)); err == nil {
		return true, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	return false, nil
}

// claudeFloorTransaction runs fn with the managed-settings.d directory under
// the lock of the lifecycle that owns Claude Code's managed settings.
type claudeFloorTransaction func(fn func(policyDir string) error) error

// reconcileClaudeVersionFloorFor is the version floor pass of a platform
// whose lifecycle, not this package, owns Claude Code's managed settings
// (Windows). It applies the floor while claudecode is published through
// machine policy and removes DefenseClaw's drop-in otherwise, inside
// transaction, never touching the hook drop-in.
func reconcileClaudeVersionFloorFor(opts Options, connectors []string, transaction claudeFloorTransaction, state *State) error {
	policy := opts.PolicyFor(claudeConnector)
	active := false
	for _, name := range MachinePolicyConnectors(opts, connectors) {
		active = active || name == claudeConnector
	}
	write := active && policy.Ownership == config.MachinePolicyOwnershipMerge &&
		opts.claudeVersionFloorMode() == config.ClaudeVersionFloorEnforce
	if !write {
		present, err := claudeVersionFloorPresent(opts)
		if err != nil || !present {
			return err
		}
	}
	return transaction(func(policyDir string) error {
		if err := requireClaudeFloorDir(opts, policyDir); err != nil {
			return err
		}
		if !active {
			return removeClaudeVersionFloor(opts, state)
		}
		return applyClaudeVersionFloor(opts, policy, state)
	})
}

// requireClaudeFloorDir refuses a transaction whose lock guards a different
// directory than the one the floor is written to.
func requireClaudeFloorDir(opts Options, policyDir string) error {
	path, err := ClaudeVersionFloorPath(opts)
	if err != nil {
		return err
	}
	want := dirFor(opts, path)
	got := strings.TrimRight(policyDir, `\/`)
	same := got == want
	if opts.goos() == "windows" {
		same = strings.EqualFold(filepath.Clean(got), filepath.Clean(want))
	}
	if !same {
		return fmt.Errorf("Claude Code managed policy lock guards %s, not %s", policyDir, want)
	}
	return nil
}

// removeClaudeVersionFloorWith removes DefenseClaw's floor drop-in inside
// transaction (the Windows uninstall).
func removeClaudeVersionFloorWith(opts Options, transaction claudeFloorTransaction, state *State) error {
	present, err := claudeVersionFloorPresent(opts)
	if err != nil || !present {
		return err
	}
	return transaction(func(policyDir string) error {
		if err := requireClaudeFloorDir(opts, policyDir); err != nil {
			return err
		}
		return removeClaudeVersionFloor(opts, state)
	})
}

// inspectClaudeVersionFloor reports requiredMinimumVersion and who sets it.
// Only a missing DefenseClaw floor that DefenseClaw is supposed to write is a
// conflict; an administrator value always wins and is reported.
func inspectClaudeVersionFloor(opts Options, policy config.ResolvedConnectorPolicy, sources []claudeSource, higher []higherClaudeSource, state *State) error {
	plan, err := planClaudeVersionFloor(opts, sources, higher)
	if err != nil {
		return err
	}
	floor := &VersionFloorState{Mode: plan.mode, Floor: plan.floor, Path: plan.path, Owner: VersionFloorOwnerNone}
	state.VersionFloor = floor
	if plan.floor == "" {
		state.detail("Claude Code version floor: no verified hook contract has a lower bound, so DefenseClaw sets no requiredMinimumVersion")
		return nil
	}
	switch {
	case plan.admin != nil:
		floor.Owner = VersionFloorOwnerAdministrator
		floor.Source = plan.admin.source
		floor.Value = claudeFloorValueText(plan.admin.value)
		version, _ := plan.admin.value.(string)
		version = strings.TrimSpace(version)
		switch {
		case !claudeVersionPattern.MatchString(version):
			floor.Invalid = true
			state.detail("Claude Code version floor: %s sets requiredMinimumVersion to %s, which is not a major.minor.patch version; Claude Code ignores an invalid value, so builds below %s may start", plan.admin.source, floor.Value, plan.floor)
		case compareVersions(version, plan.floor) < 0:
			floor.BelowFloor = true
			state.detail("Claude Code version floor: %s sets requiredMinimumVersion %s, below %s, the lowest Claude Code version with a verified DefenseClaw hook contract; builds from %s up to %s start without one", plan.admin.source, version, plan.floor, version, plan.floor)
		default:
			state.detail("Claude Code version floor: %s sets requiredMinimumVersion %s; DefenseClaw keeps the administrator's value and writes no floor of its own", plan.admin.source, version)
		}
		if plan.owned && policy.Ownership == config.MachinePolicyOwnershipMerge {
			state.detail("Claude Code version floor: DefenseClaw's %s is still present; the next reconcile removes it", plan.path)
		}
	case plan.owned:
		floor.Owner = VersionFloorOwnerDefenseClaw
		floor.Source = plan.path
		floor.Value = claudeVersionFloorFileValue(plan.current)
		state.detail("Claude Code version floor: DefenseClaw's %s sets requiredMinimumVersion %s; Claude Code builds below it refuse to start from their next session (builds that predate the setting ignore it)", plan.path, floor.Value)
		switch {
		case plan.wanted(policy) && floor.Value != plan.floor:
			state.detail("Claude Code version floor: the next reconcile raises it to %s", plan.floor)
		case !plan.wanted(policy) && policy.Ownership == config.MachinePolicyOwnershipMerge:
			state.detail("Claude Code version floor: the next reconcile removes it (version_floor: %s)", plan.mode)
		}
	default:
		switch {
		case plan.mode == config.ClaudeVersionFloorEnforce && policy.Ownership == config.MachinePolicyOwnershipMerge:
			state.conflict("Claude Code version floor: no managed settings source sets requiredMinimumVersion and DefenseClaw's %s is missing, so Claude Code builds below %s can start; the next reconcile writes it", plan.path, plan.floor)
		case plan.mode == config.ClaudeVersionFloorEnforce:
			state.detail("Claude Code version floor: no managed settings source sets requiredMinimumVersion; deploy the output of `defenseclaw-gateway enterprise policy export --connector claudecode --format version-floor` through your policy tool, or set the key yourself, so Claude Code builds below %s refuse to start", plan.floor)
		case plan.mode == config.ClaudeVersionFloorReport:
			state.detail("Claude Code version floor: no managed settings source sets requiredMinimumVersion, so Claude Code builds below %s can start (version_floor: report)", plan.floor)
		default:
			state.detail("Claude Code version floor: version_floor: off; DefenseClaw does not manage requiredMinimumVersion")
		}
	}
	if plan.replacing != "" && (plan.admin == nil || !plan.admin.higher) && (floor.Owner != VersionFloorOwnerNone || plan.mode != config.ClaudeVersionFloorOff) {
		state.detail("Claude Code version floor: %s outranks the managed settings files, so Claude Code ignores requiredMinimumVersion there; set it in %s", plan.replacing, plan.replacing)
	}
	return nil
}

func claudeVersionFloorFileValue(data []byte) string {
	doc, err := decodeOrderedObject(data)
	if err != nil {
		return ""
	}
	value, _ := doc.get(claudeVersionFloorKey)
	return claudeFloorValueText(value)
}

// claudeFloorValueText renders a decoded JSON value for a report.
func claudeFloorValueText(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	return string(canonicalJSON(value))
}

// exportClaudeVersionFloor renders DefenseClaw's floor drop-in for an
// administrator's own policy tool.
func exportClaudeVersionFloor(opts Options) ([]byte, error) {
	if opts.claudeVersionFloorMode() == config.ClaudeVersionFloorOff {
		return nil, errors.New("the Claude Code version floor is off (enterprise.machine_policy.claudecode.version_floor)")
	}
	floor := ClaudeVersionFloor()
	if floor == "" {
		return nil, errors.New("no verified Claude Code hook contract has a lower bound")
	}
	return renderClaudeVersionFloor(floor)
}
