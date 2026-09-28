// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
)

// codeHookContractUnverified names a guardian target whose agent version
// has no verified DefenseClaw hook contract. The guardian refuses to
// install hooks it cannot parse or enforce, so that agent runs without
// DefenseClaw until an administrator acts.
const codeHookContractUnverified = "hook_contract_unverified"

// codeGuardianTargetFailed names any other guardian target the guardian
// could not protect.
const codeGuardianTargetFailed = "guardian_target_failed"

// guardianStateFile is the guardian state the gateway reads in DataDir.
const guardianStateFile = "hook_guardian_state.json"

var unverifiedVersionPattern = regexp.MustCompile(`agent version "([^"]*)"`)

// describeHookContracts reports every guardian target the guardian could
// not protect (an unverified hook contract gets its own code) and marks the
// deployment security-incomplete: an unprotected agent must never look like
// a healthy deployment.
func (l *lifecycle) describeHookContracts() {
	env, r := l.env, l.result
	data, err := readBounded(env.P(filepath.Join(env.Layout.DataDir, guardianStateFile)), 4<<20)
	if err != nil {
		return
	}
	var state struct {
		Results []struct {
			User      string `json:"user"`
			Connector string `json:"connector"`
			OK        bool   `json:"ok"`
			Error     string `json:"error"`
		} `json:"results"`
	}
	if json.Unmarshal(data, &state) != nil {
		return
	}
	var unverified, failed []string
	for _, result := range state.Results {
		if result.OK || strings.TrimSpace(result.Error) == "" {
			continue
		}
		if !unverifiedHookContractError(result.Error) {
			reason := boundedGuardianReason(strings.TrimSpace(strings.TrimPrefix(result.Error, "enterprise hooks: ")))
			failed = append(failed, fmt.Sprintf("%s for user %s is not protected: %s", result.Connector, result.User, reason))
			continue
		}
		version := "unknown"
		if match := unverifiedVersionPattern.FindStringSubmatch(result.Error); match != nil && match[1] != "" {
			version = match[1]
		}
		unverified = append(unverified, fmt.Sprintf(
			"%s %s for user %s has no verified DefenseClaw hook contract, so it runs without DefenseClaw hooks; pin a verified agent version or add a verified hook contract",
			result.Connector, version, result.User))
	}
	if len(unverified)+len(failed) == 0 {
		return
	}
	sort.Strings(unverified)
	sort.Strings(failed)
	for _, message := range unverified {
		r.AddWarning(codeHookContractUnverified, message)
	}
	for _, message := range failed {
		r.AddWarning(codeGuardianTargetFailed, message)
	}
	r.SecurityComplete = false
}

// codeGuardianReportPending names a change whose guardian report did not
// arrive in time.
const codeGuardianReportPending = "guardian_report_pending"

// awaitGuardianReport waits, bounded by GuardianReportTimeout, for the
// guardian to publish its target report after since (the restarted guardian
// reconciles every manifest target under the new config), so the result of
// the change names the targets it left unprotected, for example an agent
// version without a verified hook contract in the new guardrail mode.
// Without manifest targets there is nothing to wait for.
func (l *lifecycle) awaitGuardianReport(ctx context.Context, since time.Time) {
	env, r := l.env, l.result
	manifest, err := enterprisehooks.LoadManifest(env.P(env.Layout.ManifestPath))
	if err != nil || len(manifest.Targets) == 0 {
		return
	}
	deadline := env.Now().Add(env.GuardianReportTimeout)
	for {
		if updated, ok := l.guardianReportedAt(); ok && !updated.Before(since) {
			return
		}
		if !env.Now().Before(deadline) {
			r.AddWarning(codeGuardianReportPending, fmt.Sprintf(
				"the hook guardian has not reported on its %d manifest targets since this change, so their protection is not confirmed yet; run `%s` in a minute to see it",
				len(manifest.Targets), env.lifecycleCommand("status")))
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(env.PollInterval):
		}
	}
}

// guardianReportedAt is when the guardian last wrote its target report.
func (l *lifecycle) guardianReportedAt() (time.Time, bool) {
	env := l.env
	data, err := readBounded(env.P(filepath.Join(env.Layout.DataDir, guardianStateFile)), 4<<20)
	if err != nil {
		return time.Time{}, false
	}
	var state struct {
		UpdatedAt string `json:"updated_at"`
	}
	if json.Unmarshal(data, &state) != nil {
		return time.Time{}, false
	}
	updated, err := time.Parse(time.RFC3339Nano, state.UpdatedAt)
	return updated, err == nil
}

// codeAgentUnprotected names an agent the enumerator found installed for an
// eligible user but could not enroll; it runs without DefenseClaw hooks.
const codeAgentUnprotected = enterprisehooks.UnprotectedCodeAgentUnprotected

// describeUnprotectedAgents reports the agents the enumerator found
// installed but could not enroll (its unprotected-agents record next to the
// manifest) and marks the deployment security-incomplete.
func (l *lifecycle) describeUnprotectedAgents() {
	env, r := l.env, l.result
	data, err := readBounded(env.P(enterprisehooks.UnprotectedAgentsPath(env.Layout.ManifestPath)), enterprisehooks.UnprotectedAgentsMaxBytes)
	if err != nil {
		return
	}
	agents, err := enterprisehooks.ParseUnprotectedAgents(data)
	if err != nil {
		r.AddWarning(codeAgentUnprotected, "the enumerator's unprotected-agents record is unreadable: "+err.Error())
		r.SecurityComplete = false
		return
	}
	for _, agent := range agents {
		r.AddWarning(agent.Code, agent.Message())
	}
	if len(agents) > 0 {
		r.SecurityComplete = false
	}
}

// guardianReasonMaxBytes bounds one guardian target reason in the result.
// Guardian errors name the refused path and end with the remedy after the
// last "; ", so the bound is generous and a longer reason keeps its remedy.
const guardianReasonMaxBytes = 1024

func boundedGuardianReason(reason string) string {
	if len(reason) <= guardianReasonMaxBytes {
		return reason
	}
	if index := strings.LastIndex(reason, "; "); index > 0 && len(reason)-index <= guardianReasonMaxBytes/2 {
		remedy := reason[index:]
		return truncateUTF8(reason[:index], guardianReasonMaxBytes-len(remedy)-len("...")) + "..." + remedy
	}
	return truncateUTF8(reason, guardianReasonMaxBytes-len("...")) + "..."
}

// truncateUTF8 cuts value to at most limit bytes without splitting a rune.
func truncateUTF8(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	for limit > 0 && !utf8.RuneStart(value[limit]) {
		limit--
	}
	return value[:limit]
}

func unverifiedHookContractError(message string) bool {
	return strings.Contains(message, "is not verified against a known hook contract") ||
		strings.Contains(message, "is not covered by a known hook contract")
}
