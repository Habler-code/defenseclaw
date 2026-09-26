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

// applyEnterpriseForeignHookGuard denies a hook invocation on a standalone
// managed host while an unapproved hook that could rewrite the tool call
// after DefenseClaw checks it is present in the agent's user or project
// config. It covers machine-policy (--enterprise-managed) and per-user
// registrations alike. The denial reuses hookexec's managed fail-closed
// path, so each connector gets its native block response carrying the
// reason (file, digest and allowlist key).
func applyEnterpriseForeignHookGuard(opts *hookexec.Options) {
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
	decision := evaluateHookForeignGuard(name, summary.HookBinary, policy, captureHookPayloadWorkingDirs(opts), opts.Home)
	if decision.Deny {
		opts.ManagedEnterprise = true
		opts.ManagedRuntimeFailure = decision.Reason
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

// evaluateHookForeignGuard scans every home and working directory the
// agent may load hooks from and merges the findings.
func evaluateHookForeignGuard(name, hookBinary string, policy enterprisepolicy.PublicConnectorPolicy, workingDirs []string, dataDir string) enterprisepolicy.GuardDecision {
	merged := enterprisepolicy.GuardDecision{}
	seen := map[string]bool{}
	if len(workingDirs) == 0 {
		workingDirs = []string{""}
	}
	for _, home := range hookForeignGuardHomes() {
		owned := perUserOwnedHookCommands(name, home, dataDir)
		for _, dir := range workingDirs {
			decision := enterprisepolicy.EvaluateForeignHooks(enterprisepolicy.GuardRequest{
				Connector:     name,
				Home:          home,
				WorkingDir:    dir,
				HookBinary:    hookBinary,
				Policy:        policy,
				Getenv:        os.Getenv,
				OwnedCommands: owned,
			})
			for _, finding := range decision.Findings {
				key := finding.Path + "\x00" + finding.Digest
				if !seen[key] {
					seen[key] = true
					merged.Findings = append(merged.Findings, finding)
				}
			}
			if decision.Deny && !merged.Deny {
				merged.Deny = true
				merged.Reason = decision.Reason
			}
		}
	}
	return merged
}

// captureHookPayloadWorkingDirs buffers the start of the hook payload to
// read the agent's working directory, then hands hookexec an identical
// stream. The process working directory is always included because the
// agent loads project hooks from where it runs.
func captureHookPayloadWorkingDirs(opts *hookexec.Options) []string {
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
		return dirs
	}
	var payload map[string]json.RawMessage
	if json.Unmarshal(buffered, &payload) != nil {
		return dirs
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
	return dirs
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
