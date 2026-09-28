// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

const builtInMatchReasonPrefix = "matched: "

// trustedBuiltInMatchReason reports whether reason consists exclusively of
// exact rule ID/title pairs from the compiled-in catalog. The equality check
// is deliberately stricter than a character allow-list: scanner-provided
// titles can contain matched literals that merely look like harmless metadata.
func trustedBuiltInMatchReason(reason string) bool {
	body, ok := strings.CutPrefix(reason, builtInMatchReasonPrefix)
	if !ok || body == "" {
		return false
	}
	labels := strings.Split(body, ", ")
	if len(labels) == 0 || len(labels) > 5 {
		return false
	}
	for _, label := range labels {
		if !trustedBuiltInFindingLabel(label) {
			return false
		}
	}
	return true
}

func trustedBuiltInFindingLabel(label string) bool {
	for _, category := range defaultRuleCategories {
		for _, rule := range category.Rules {
			base := rule.ID + ":" + rule.Title
			if label == base || label == base+" (obfuscated)" {
				return true
			}
		}
	}
	return false
}

// agentDisplayReason keeps exact, ship-authored catalog metadata readable on
// agent surfaces under the default compatibility policy while retaining the
// existing scrub for every free-form or scanner-authored reason. Explicit
// managed policies remain authoritative in both directions.
func agentDisplayReason(reason string, policy redaction.SinkPolicy) string {
	if policy != redaction.SinkPolicyDefault {
		return redaction.ReasonForSink(reason, policy)
	}
	if trustedBuiltInMatchReason(reason) {
		return reason
	}
	return redaction.ReasonForAgent(reason)
}

// notificationDisplayReason applies the same narrow catalog carve-out to OS
// notifications only under the default compatibility policy. An explicit
// managed-enterprise redact directive remains authoritative.
func notificationDisplayReason(reason string, policy redaction.SinkPolicy) string {
	if policy == redaction.SinkPolicyDefault && trustedBuiltInMatchReason(reason) {
		return reason
	}
	return redaction.ReasonForSink(reason, policy)
}

// defaultSinkDisplayReason applies the catalog carve-out to compatibility
// response bodies only when no managed override is active.
func defaultSinkDisplayReason(reason string, policy redaction.SinkPolicy) string {
	if policy == redaction.SinkPolicyDefault && trustedBuiltInMatchReason(reason) {
		return reason
	}
	return redaction.ReasonForSink(reason, policy)
}

// standaloneEnterpriseActive records whether the running deployment is the
// standalone enterprise profile, where the organization's policy decides.
// Wired next to managedEnterpriseActive by NewSidecar and the config reload.
var standaloneEnterpriseActive atomic.Bool

func setStandaloneEnterpriseActive(v bool) { standaloneEnterpriseActive.Store(v) }

// agentRuleIDPattern is the shape of a rule ID an agent message may name.
var agentRuleIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// agentVerdictReason words a block or a confirmation of a local policy rule
// for the agent's user. The bare "matched: <rule-id>:<title>" reason, with a
// custom rule's title replaced by a "<redacted len=N sha=...>" token, read
// like a broken hook, and users (and the model) went looking in their own
// agent settings. The message says DefenseClaw made the decision under the
// organization's policy (standalone enterprise) or DefenseClaw policy
// (per-user), and names the rules by ID; a compiled-in rule keeps its
// title. The audit record keeps the full source reason.
//
// Other actions and any other reason (a configured block message, a
// foreign-hook or AI Defense verdict) keep displayReason. Secure Client
// keeps its pinned wording: a managed deployment, an explicit managed
// redaction directive, or the managed agent-reason carve-out (which hands
// the agent the raw reason) leave displayReason unchanged.
func agentVerdictReason(action, sourceReason, displayReason string, policy redaction.SinkPolicy) string {
	if action != "block" && action != "confirm" {
		return displayReason
	}
	if managedEnterpriseActive.Load() || policy != redaction.SinkPolicyDefault {
		return displayReason
	}
	if displayReason == sourceReason && !trustedBuiltInMatchReason(sourceReason) {
		return displayReason
	}
	rules := agentMatchedRules(sourceReason)
	if rules == "" {
		return displayReason
	}
	standalone := standaloneEnterpriseActive.Load()
	switch {
	case action == "block" && standalone:
		return "DefenseClaw blocked this action under your organization's policy (" + rules + "). Contact your administrator if you need it allowed."
	case action == "block":
		return "DefenseClaw policy blocked this action (" + rules + ")."
	case standalone:
		return "DefenseClaw needs your confirmation for this action under your organization's policy (" + rules + ")."
	default:
		return "DefenseClaw policy needs your confirmation for this action (" + rules + ")."
	}
}

// agentOrderedRulePrefix starts the note an ordered tool-call chain match
// appends to a reason (agent_hook_chain.go).
const agentOrderedRulePrefix = "matched ordered safety rule: "

// agentMatchedRules names the rules of a "matched: <rule-id>:<title>, ..."
// reason, and of any ordered-chain note appended to it: "rule ID" or
// "rules ID1, ID2". A title from the compiled-in catalog is kept ("rule ID:
// Title"); any other title (a rule pack's, or a scanner's, which can carry
// matched text) is left to the audit record. It returns "" for any other
// reason.
func agentMatchedRules(reason string) string {
	var items []string
	seen := make(map[string]bool)
	add := func(id, item string) {
		if len(items) == 5 || seen[id] || !agentRuleIDPattern.MatchString(id) {
			return
		}
		seen[id] = true
		items = append(items, item)
	}
	for i, part := range strings.Split(reason, "; ") {
		switch {
		case i == 0 && strings.HasPrefix(part, builtInMatchReasonPrefix):
			for _, label := range strings.Split(strings.TrimPrefix(part, builtInMatchReasonPrefix), ", ") {
				id, title, found := strings.Cut(label, ":")
				if !found {
					continue
				}
				item := id
				if trustedBuiltInFindingLabel(label) {
					item = id + ": " + title
				}
				add(id, item)
			}
		case strings.HasPrefix(part, agentOrderedRulePrefix):
			for _, id := range strings.Split(strings.TrimPrefix(part, agentOrderedRulePrefix), ", ") {
				add(id, id)
			}
		}
	}
	switch len(items) {
	case 0:
		return ""
	case 1:
		return "rule " + items[0]
	}
	return "rules " + strings.Join(items, ", ")
}
