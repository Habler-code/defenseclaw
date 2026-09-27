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
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

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
			reason := strings.TrimSpace(strings.TrimPrefix(result.Error, "enterprise hooks: "))
			if len(reason) > 240 {
				reason = reason[:240] + "..."
			}
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

func unverifiedHookContractError(message string) bool {
	return strings.Contains(message, "is not verified against a known hook contract") ||
		strings.Contains(message, "is not covered by a known hook contract")
}
