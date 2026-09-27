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
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// hookForeignGuardPayloadLimit bounds how much of the hook payload the
// guard buffers to find the agent's working directory; hookexec still
// applies its own cap to the full stream.
const hookForeignGuardPayloadLimit = 1 << 20

// hookForeignGuardSummaryPath resolves the standalone public machine policy
// summary. It is replaceable in tests. A host without a standalone layout
// (Secure Client, unmanaged) has no summary, and the guard is a no-op.
var hookForeignGuardSummaryPath = func() (string, bool) {
	layout, _, _, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		return "", false
	}
	return enterprisepolicy.PublicPolicyPathFor(layout), true
}

var hookForeignGuardLoad = enterprisepolicy.LoadPublicPolicy

// hookForeignGuardRecord records a block for the guardian to report
// (replaceable in tests).
var hookForeignGuardRecord = enterprisepolicy.RecordForeignHookBlock

// applyEnterpriseForeignHookGuard denies a hook invocation on a standalone
// managed host while an unapproved hook that could rewrite the tool call
// after DefenseClaw checks it is present in the agent's user or project
// config. It covers machine-policy (--enterprise-managed) and per-user
// registrations alike. The denial reuses hookexec's managed fail-closed
// path, so each connector gets its native block response carrying the
// reason (file, digest and allowlist key).
func applyEnterpriseForeignHookGuard(opts *hookexec.Options) {
	startedAt := time.Now()
	if opts.ManagedEnterprise && strings.TrimSpace(opts.ManagedRuntimeFailure) != "" {
		return
	}
	path, ok := hookForeignGuardSummaryPath()
	if !ok {
		return
	}
	summary, err := hookForeignGuardLoad(path)
	if errors.Is(err, enterprisepolicy.ErrNoPublicPolicy) {
		return
	}
	if err != nil {
		opts.ManagedEnterprise = true
		opts.ManagedRuntimeFailure = "enterprise_machine_policy_summary_untrusted"
		return
	}
	name := strings.ToLower(strings.TrimSpace(opts.Connector))
	policy, ok := summary.Connectors[name]
	if !ok || !policy.Guard {
		return
	}
	// The scan is part of this invocation: hookexec's request budget starts
	// here, and the scan itself stops (failing closed) well inside it, so a
	// slow or flooded tree can never run into the agent's own hook timeout
	// (which Copilot treats as allow).
	opts.StartedAt = startedAt
	deadline := startedAt.Add(hookForeignGuardScanBudget(name, opts.Event))
	workingDirs, payloadEvent := captureHookPayloadWorkingDirs(opts)
	decision, accountHome := evaluateHookForeignGuard(name, summary.HookBinary, policy, workingDirs, deadline)
	if decision.Deny {
		opts.ManagedEnterprise = true
		opts.ManagedRuntimeFailure = decision.Reason
		// The block never reaches the gateway, and the managed hook's own
		// failure log is not user-writable: leave a record in the user's
		// data directory for the guardian to report (best effort).
		event := strings.TrimSpace(opts.Event)
		if event == "" {
			event = payloadEvent
		}
		_ = hookForeignGuardRecord(accountHome, name, event, decision, time.Now())
		return
	}
	stderr := opts.Stderr
	if stderr == nil {
		stderr = os.Stderr
	}
	for _, finding := range decision.Findings {
		if !finding.Allowed {
			fmt.Fprintf(stderr, "defenseclaw: warning: unapproved %s hook in %s (sha256:%s); your organization reports it but allows it to run\n", name, finding.Path, finding.Digest)
		}
	}
}

// standaloneForeignHookGuardBinary is the administrator-owned hook binary
// the standalone Amp and OpenCode plugins run for the foreign-hook guard
// (those plugins call the gateway directly, so the hook-time guard would
// otherwise never run for them). Empty for every other connector and on
// any non-standalone profile, so Secure Client and per-user installs render
// the plugins unchanged.
func standaloneForeignHookGuardBinary(connectorName string) string {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return ""
	}
	switch strings.ToLower(strings.TrimSpace(connectorName)) {
	case "amp", enterprisepolicy.ConnectorOpenCode:
	default:
		return ""
	}
	layout, programFiles, programData, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		return ""
	}
	opts, err := enterprisepolicy.StandaloneOptions(layout, programFiles, programData, cfg)
	if err != nil {
		return ""
	}
	return opts.HookBinary
}

// hookForeignGuardHomes lists the homes an agent may read hook config
// from: the account's home and, when different, the home its environment
// names.
func hookForeignGuardHomes(accountHome string) []string {
	homes := appendDistinctAbs(nil, accountHome)
	for _, home := range hookForeignGuardEnvHomes() {
		homes = appendDistinctAbs(homes, home)
	}
	return homes
}

// foreignHookCheckResult is the JSON the in-agent plugins read from
// `hook --foreign-hook-check`. Anything but {"deny": false} blocks.
type foreignHookCheckResult struct {
	Deny     bool     `json:"deny"`
	Reason   string   `json:"reason,omitempty"`
	Warnings []string `json:"warnings,omitempty"`
}

// runForeignHookCheck evaluates the foreign-hook guard for an in-agent
// plugin (Amp, OpenCode) that calls the gateway directly. It reads the
// plugin's {hook_event_name, cwd} from stdin, applies the same summary
// trust, scan and budget as the hook-time guard, records a block for the
// guardian, and always exits 0 with one JSON object: the plugin treats a
// missing or malformed answer as a block. Hosts without a standalone
// summary answer allow, like the hook-time guard.
func runForeignHookCheck(connectorName string, stdin io.Reader, stdout io.Writer) int {
	startedAt := time.Now()
	result := foreignHookCheckResult{}
	defer func() {
		_ = json.NewEncoder(stdout).Encode(result)
	}()
	path, ok := hookForeignGuardSummaryPath()
	if !ok {
		return 0
	}
	summary, err := hookForeignGuardLoad(path)
	if errors.Is(err, enterprisepolicy.ErrNoPublicPolicy) {
		return 0
	}
	if err != nil {
		result = foreignHookCheckResult{Deny: true, Reason: "enterprise_machine_policy_summary_untrusted"}
		return 0
	}
	name := strings.ToLower(strings.TrimSpace(connectorName))
	policy, ok := summary.Connectors[name]
	if !ok || !policy.Guard {
		return 0
	}
	opts := hookexec.Options{Connector: name, Stdin: stdin}
	workingDirs, event := captureHookPayloadWorkingDirs(&opts)
	decision, accountHome := evaluateHookForeignGuard(name, summary.HookBinary, policy, workingDirs, startedAt.Add(hookForeignGuardMaxScan))
	if decision.Deny {
		_ = hookForeignGuardRecord(accountHome, name, event, decision, time.Now())
		result = foreignHookCheckResult{Deny: true, Reason: decision.Reason}
		return 0
	}
	for _, finding := range decision.Findings {
		if !finding.Allowed {
			result.Warnings = append(result.Warnings, fmt.Sprintf("unapproved %s hook in %s (sha256:%s); your organization reports it but allows it to run", name, finding.Path, finding.Digest))
		}
	}
	return 0
}

// hookForeignGuardMaxScan caps the foreign-hook scan; real hook trees
// take milliseconds.
const hookForeignGuardMaxScan = 5 * time.Second

// hookForeignGuardScanBudget is at most half the invocation's request
// budget, so a denial is always delivered before the agent's timeout.
func hookForeignGuardScanBudget(connector, event string) time.Duration {
	budget := hookexec.RequestTimeout(connector, event) / 2
	if budget > hookForeignGuardMaxScan || budget <= 0 {
		budget = hookForeignGuardMaxScan
	}
	return budget
}

// evaluateHookForeignGuard scans every home and working directory the
// agent may load hooks from, in one pass that reads each path once and
// stops at the first unapproved finding. DefenseClaw's own per-user
// registration is recognized only under the account's home: the hook's
// data directory and $HOME come from the agent's environment
// (DEFENSECLAW_HOME, HOME), which the user controls.
func evaluateHookForeignGuard(name, hookBinary string, policy enterprisepolicy.PublicConnectorPolicy, workingDirs []string, deadline time.Time) (enterprisepolicy.GuardDecision, string) {
	accountHome := hookForeignGuardAccountHome()
	owned := []string{}
	if accountHome != "" {
		owned = perUserOwnedHookCommands(name, accountHome, "")
	}
	homes := hookForeignGuardHomes(accountHome)
	if len(homes) == 0 {
		return enterprisepolicy.GuardDecision{
			Deny:   true,
			Reason: hookexec.ForeignHookBlockedReasonPrefix + " your organization blocks " + name + " hooks it has not approved, and DefenseClaw cannot determine your home directory to check for them.",
		}, ""
	}
	request := enterprisepolicy.GuardRequest{
		Connector:           name,
		Home:                homes[0],
		Homes:               homes[1:],
		AccountHome:         accountHome,
		HookBinary:          hookBinary,
		Policy:              policy,
		Getenv:              os.Getenv,
		OwnedCommands:       owned,
		Deadline:            deadline,
		StopAtFirstBlocking: true,
	}
	if len(workingDirs) > 0 {
		request.WorkingDir = workingDirs[0]
		request.WorkingDirs = workingDirs[1:]
	}
	return enterprisepolicy.EvaluateForeignHooks(request), accountHome
}

// captureHookPayloadWorkingDirs buffers the start of the hook payload to
// read the agent's working directory (and the event name, for the block
// record), then hands hookexec an identical stream. The process working
// directory is always included because the agent loads project hooks from
// where it runs.
func captureHookPayloadWorkingDirs(opts *hookexec.Options) ([]string, string) {
	dirs := []string{}
	if cwd, err := os.Getwd(); err == nil {
		dirs = appendDistinctAbs(dirs, cwd)
	}
	source := opts.Stdin
	if source == nil {
		source = os.Stdin
	}
	buffered, err := io.ReadAll(io.LimitReader(source, hookForeignGuardPayloadLimit))
	opts.Stdin = io.MultiReader(bytes.NewReader(buffered), source)
	if err != nil {
		return dirs, ""
	}
	var payload map[string]json.RawMessage
	if json.Unmarshal(buffered, &payload) != nil {
		return dirs, ""
	}
	event := ""
	for _, key := range []string{"hook_event_name", "event"} {
		if json.Unmarshal(payload[key], &event) == nil && strings.TrimSpace(event) != "" {
			break
		}
		event = ""
	}
	for _, key := range []string{"cwd", "working_directory", "workingDirectory"} {
		var value string
		if json.Unmarshal(payload[key], &value) == nil {
			dirs = appendDistinctAbs(dirs, value)
		}
	}
	for _, key := range []string{"workspace_roots", "workspaceRoots"} {
		var values []string
		if json.Unmarshal(payload[key], &values) == nil {
			for _, value := range values {
				dirs = appendDistinctAbs(dirs, value)
			}
		}
	}
	return dirs, strings.TrimSpace(event)
}

// perUserOwnedHookCommands lists DefenseClaw's own per-user registration
// commands for the default per-user data dir under home and any explicit
// data dir.
func perUserOwnedHookCommands(name, home, dataDir string) []string {
	dirs := appendDistinctAbs(nil, filepath.Join(home, ".defenseclaw"))
	dirs = appendDistinctAbs(dirs, dataDir)
	owned := []string{}
	for _, dir := range dirs {
		owned = append(owned, connector.PerUserOwnedHookCommands(name, dir)...)
	}
	return owned
}

func appendDistinctAbs(list []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" || !filepath.IsAbs(value) {
		return list
	}
	value = filepath.Clean(value)
	for _, existing := range list {
		if existing == value {
			return list
		}
	}
	return append(list, value)
}
