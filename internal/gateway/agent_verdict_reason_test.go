// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

func useAgentVerdictProfile(t *testing.T, standalone, secureClient bool) {
	t.Helper()
	previousStandalone, previousManaged := standaloneEnterpriseActive.Load(), managedEnterpriseActive.Load()
	setStandaloneEnterpriseActive(standalone)
	SetManagedEnterpriseActive(secureClient)
	t.Cleanup(func() {
		setStandaloneEnterpriseActive(previousStandalone)
		SetManagedEnterpriseActive(previousManaged)
	})
}

// A rule-pack rule, whose title the agent surface redacts.
const certMarkerReason = "matched: CERT-S3-MARKER-BLOCK:Certification marker (block)"

const (
	orgBlockWording     = "DefenseClaw blocked this action under your organization's policy (rule CERT-S3-MARKER-BLOCK). Do not retry it in another form. Contact your administrator if you need it allowed."
	orgConfirmWording   = "DefenseClaw needs your confirmation for this action under your organization's policy (rule CERT-S3-MARKER-BLOCK)."
	userBlockWording    = "DefenseClaw policy blocked this action (rule CERT-S3-MARKER-BLOCK). Do not retry it in another form."
	userConfirmWording  = "DefenseClaw policy needs your confirmation for this action (rule CERT-S3-MARKER-BLOCK)."
	redactedTokenPrefix = "<redacted"
)

func TestAgentVerdictReasonNamesDefenseClawPolicyAndTheRule(t *testing.T) {
	display := agentDisplayReason(certMarkerReason, redaction.SinkPolicyDefault)
	if !strings.Contains(display, redactedTokenPrefix) {
		t.Fatalf("precondition: a rule-pack title is redacted on the agent surface, got %q", display)
	}
	for _, test := range []struct {
		name       string
		standalone bool
		action     string
		want       string
	}{
		{"standalone block", true, "block", orgBlockWording},
		{"standalone confirm", true, "confirm", orgConfirmWording},
		{"per-user block", false, "block", userBlockWording},
		{"per-user confirm", false, "confirm", userConfirmWording},
	} {
		t.Run(test.name, func(t *testing.T) {
			useAgentVerdictProfile(t, test.standalone, false)
			if got := agentVerdictReason(test.action, certMarkerReason, display, redaction.SinkPolicyDefault); got != test.want {
				t.Fatalf("got %q\nwant %q", got, test.want)
			}
		})
	}

	useAgentVerdictProfile(t, true, false)
	for _, action := range []string{"allow", "alert"} {
		if got := agentVerdictReason(action, certMarkerReason, display, redaction.SinkPolicyDefault); got != display {
			t.Fatalf("%s reason rewritten to %q", action, got)
		}
	}
	for _, reason := range []string{
		"enterprise_foreign_hook_blocked: your organization blocks copilot hooks it has not approved",
		"Blocked by the security team",
		"",
	} {
		if got := agentVerdictReason("block", reason, reason, redaction.SinkPolicyDefault); got != reason {
			t.Fatalf("non-rule reason %q rewritten to %q", reason, got)
		}
	}

	// A local rule merged with an AI Defense or judge verdict: the merged
	// reason names the other lane's reason too, so the rule-only wording
	// would drop the reason that decided (and could blame an alert-only
	// rule). Such a reason keeps its display text.
	for _, source := range []string{
		certMarkerReason + "; Cisco AI Defense: prompt injection detected",
		certMarkerReason + "; judge-injection: instruction override",
		"matched ordered safety rule: CHAIN-1; judge-exfil: upload of a credential",
	} {
		display := agentDisplayReason(source, redaction.SinkPolicyDefault)
		if got := agentVerdictReason("block", source, display, redaction.SinkPolicyDefault); got != display {
			t.Fatalf("merged reason %q rewritten to %q", source, got)
		}
	}
	// The approval fallback's note is not another verdict: the rule decided.
	source := certMarkerReason + "; " + approvalUnsupportedNote
	if got := agentVerdictReason("block", source, agentDisplayReason(source, redaction.SinkPolicyDefault), redaction.SinkPolicyDefault); got != orgBlockWording {
		t.Fatalf("approval fallback reason = %q, want %q", got, orgBlockWording)
	}
}

// A rule from a loaded rule pack keeps its title: the pack author wrote it,
// unlike a scanner title that can carry matched text.
func TestAgentVerdictReasonNamesALoadedRulePackTitle(t *testing.T) {
	const connectorName = "agent-verdict-title-pack"
	pack := mustLoadRulePack(t, filepath.Join(guardrailPoliciesRoot(t), "default"))
	added := false
	for index := range pack.RuleFiles {
		if pack.RuleFiles[index].Category != "command" {
			continue
		}
		pack.RuleFiles[index].Rules = append(pack.RuleFiles[index].Rules, guardrail.RuleDefYAML{
			ID:         "CERT-S3-MARKER-BLOCK",
			Pattern:    `(?i)\bcert-s3-marker-block\b`,
			Title:      "Certification marker (block)",
			Severity:   "HIGH",
			Confidence: 0.99,
		})
		added = true
		break
	}
	if !added {
		t.Fatal("the default pack has no command rule file")
	}
	if err := ApplyConnectorRulePackOverrides(connectorName, pack); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { RemoveConnectorRulePackOverrides(connectorName) })

	useAgentVerdictProfile(t, true, false)
	display := agentDisplayReason(certMarkerReason, redaction.SinkPolicyDefault)
	want := "DefenseClaw blocked this action under your organization's policy (rule CERT-S3-MARKER-BLOCK: Certification marker (block)). Do not retry it in another form. Contact your administrator if you need it allowed."
	if got := agentVerdictReason("block", certMarkerReason, display, redaction.SinkPolicyDefault); got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	// A title the pack does not have stays in the audit only.
	other := "matched: CERT-S3-MARKER-BLOCK:secret value 1234"
	if got := agentVerdictReason("block", other, agentDisplayReason(other, redaction.SinkPolicyDefault), redaction.SinkPolicyDefault); strings.Contains(got, "secret value") {
		t.Fatalf("a title outside the loaded pack reached the agent: %q", got)
	}
}

func TestAgentVerdictReasonKeepsSecureClientWording(t *testing.T) {
	useAgentVerdictProfile(t, false, true)
	display := agentDisplayReason(certMarkerReason, redaction.SinkPolicyRedact)
	if got := agentVerdictReason("block", certMarkerReason, display, redaction.SinkPolicyRedact); got != display {
		t.Fatalf("Secure Client block reason changed to %q", got)
	}
	// An explicit managed directive or the raw carve-out also keep the text.
	SetManagedEnterpriseActive(false)
	if got := agentVerdictReason("block", certMarkerReason, display, redaction.SinkPolicyRedact); got != display {
		t.Fatalf("managed redaction directive reason changed to %q", got)
	}
	if got := agentVerdictReason("block", certMarkerReason, certMarkerReason, redaction.SinkPolicyDefault); got != certMarkerReason {
		t.Fatalf("carve-out raw reason changed to %q", got)
	}
}

func TestAgentMatchedRulesNamesRulesByID(t *testing.T) {
	var builtIn string
	var builtInID, builtInTitle string
	for _, category := range defaultRuleCategories {
		for _, rule := range category.Rules {
			if rule.ID != "" && rule.Title != "" && agentRuleIDPattern.MatchString(rule.ID) && !strings.Contains(rule.Title, ", ") {
				builtInID, builtInTitle = rule.ID, rule.Title
				builtIn = rule.ID + ":" + rule.Title
				break
			}
		}
		if builtIn != "" {
			break
		}
	}
	if builtIn == "" {
		t.Fatal("no compiled-in rule to test with")
	}
	for _, test := range []struct{ reason, want string }{
		{certMarkerReason, "rule CERT-S3-MARKER-BLOCK"},
		{"matched: " + builtIn, "rule " + builtInID + ": " + builtInTitle},
		{"matched: A-1:first, second part, B.2:other, A-1:again", "rules A-1, B.2"},
		{"matched: A-1:x; human approval unsupported on this connector surface; failing closed", "rule A-1"},
		{"matched: A-1:x; Cisco AI Defense: blocked", ""},
		{"matched: A-1:x; matched ordered safety rule: CHAIN-1, CHAIN-2", "rules A-1, CHAIN-1, CHAIN-2"},
		{"matched ordered safety rule: CHAIN-1", "rule CHAIN-1"},
		{"matched: bad id:x", ""},
		{"matched:", ""},
		{"no rule matched", ""},
	} {
		if got := agentMatchedRules(test.reason); got != test.want {
			t.Fatalf("agentMatchedRules(%q) = %q, want %q", test.reason, got, test.want)
		}
	}
}

// TestHookResponsesCarryTheDefenseClawPolicyWording checks every agent
// surface: Claude Code, Codex, the generic connector hooks and the inspect
// API the plugin connectors use.
func TestHookResponsesCarryTheDefenseClawPolicyWording(t *testing.T) {
	useAgentVerdictProfile(t, true, false)
	assertWording := func(surface string, value any, want string) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		text := string(data)
		if !strings.Contains(text, want) || strings.Contains(text, redactedTokenPrefix) {
			t.Fatalf("%s response %s\nwant %q and no redaction token", surface, text, want)
		}
	}

	claude := claudeCodeResponseFor(claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "Bash"},
		"block", "block", "CRITICAL", certMarkerReason, []string{"CERT-S3-MARKER-BLOCK"}, "action", true)
	if claude.Reason != orgBlockWording {
		t.Fatalf("Claude Code reason = %q", claude.Reason)
	}
	assertWording("Claude Code", claude.ClaudeCodeOutput, orgBlockWording)
	ask := claudeCodeResponseFor(claudeCodeHookRequest{HookEventName: "PreToolUse", ToolName: "Bash"},
		"confirm", "confirm", "HIGH", certMarkerReason, nil, "action", false)
	assertWording("Claude Code ask", ask.ClaudeCodeOutput, orgConfirmWording)

	codex := codexResponseFor("PreToolUse", "block", "block", "CRITICAL", certMarkerReason, nil, "action", true)
	if codex.Reason != orgBlockWording {
		t.Fatalf("Codex reason = %q", codex.Reason)
	}
	assertWording("Codex", codex.CodexOutput, orgBlockWording)

	copilot := agentHookResponseFor(agentHookRequest{ConnectorName: "copilot", HookEventName: "preToolUse", ToolName: "bash"},
		"block", "block", "CRITICAL", certMarkerReason, nil, "action", true, connector.HookCapability{})
	if copilot.Reason != orgBlockWording {
		t.Fatalf("generic hook reason = %q", copilot.Reason)
	}

	inspect := (&ToolInspectVerdict{Action: "block", Severity: "CRITICAL", Reason: certMarkerReason}).sanitizeForResponse(false)
	if inspect.Reason != orgBlockWording {
		t.Fatalf("inspect API reason = %q", inspect.Reason)
	}
	// The source reason stays intact for the audit record.
	if claude.SourceReason != certMarkerReason || codex.SourceReason != certMarkerReason {
		t.Fatalf("source reasons changed: %q %q", claude.SourceReason, codex.SourceReason)
	}
}
