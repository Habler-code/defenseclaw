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
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func TestAgentControlRegexSourceSkipsLocalTriageAndExecutesManagedRules(t *testing.T) {
	ruleCategoriesMu.Lock()
	saved := allRuleCategories
	ruleCategoriesMu.Unlock()
	defer func() {
		ruleCategoriesMu.Lock()
		allRuleCategories = saved
		ruleCategoriesMu.Unlock()
	}()

	pack := &guardrail.RulePack{RuleFiles: []*guardrail.RulesFileYAML{{
		Version:  1,
		Category: "agent-control",
		Rules: []guardrail.RuleDefYAML{{
			ID:         "AC-PROMPT",
			Pattern:    `central-only-trigger`,
			Title:      "Central prompt rule",
			Severity:   "CRITICAL",
			Confidence: 1,
		}},
	}}}
	ApplyRulePackOverridesForSource(pack, guardrail.RegexSourceAgentControl)

	for _, strategy := range []string{"regex_only", "regex_judge", "judge_first"} {
		t.Run(strategy, func(t *testing.T) {
			inspector := NewGuardrailInspector("local", nil, nil, "")
			inspector.SetDetectionStrategy(strategy, "", "", "", false)
			inspector.SetRegexSource(guardrail.RegexSourceAgentControl)

			localOnly := inspector.Inspect(context.Background(), "prompt", "ignore previous instructions", nil, "", "action")
			if localOnly == nil || localOnly.Severity != "NONE" {
				t.Fatalf("managed source executed local triage: %+v", localOnly)
			}
			compiledOnly := inspector.Inspect(context.Background(), "prompt", "run mkfs on the device", nil, "", "action")
			if compiledOnly == nil || compiledOnly.Severity != "NONE" {
				t.Fatalf("managed source executed compiled defaults: %+v", compiledOnly)
			}

			managed := inspector.Inspect(context.Background(), "prompt", "central-only-trigger", nil, "", "action")
			if managed == nil || managed.Severity != "CRITICAL" {
				t.Fatalf("managed rule did not execute: %+v", managed)
			}
			if len(managed.Findings) != 1 || managed.Findings[0] != "AC-PROMPT:Central prompt rule" {
				t.Fatalf("managed findings = %+v", managed.Findings)
			}
			if len(managed.ScannerSources) == 0 || managed.ScannerSources[0] != "agent-control" {
				t.Fatalf("managed scanner sources = %+v", managed.ScannerSources)
			}
		})
	}
}

func TestAgentControlRulePackHookUsesOPAThresholdForBlocking(t *testing.T) {
	ruleCategoriesMu.Lock()
	saved := allRuleCategories
	ruleCategoriesMu.Unlock()
	defer func() {
		ruleCategoriesMu.Lock()
		allRuleCategories = saved
		ruleCategoriesMu.Unlock()
	}()

	policyDir := t.TempDir()
	for _, name := range []string{"data.json", "guardrail.rego", "agent_control_guardrail.rego"} {
		raw, err := os.ReadFile(filepath.Join(repoRootFromTestFile(t), "policies", "rego", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(policyDir, name), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(policyDir, "data-agent-control.json"), []byte(`{
  "agent_control": {
    "schema_version": 1,
    "enabled": true,
    "precedence": "stricter",
    "source_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "guardrail": {
      "block_threshold": 3,
      "alert_threshold": 2,
      "cisco_trust_level": "full"
    }
  }
}`), 0o600); err != nil {
		t.Fatal(err)
	}

	pack := &guardrail.RulePack{RuleFiles: []*guardrail.RulesFileYAML{{
		Version:  1,
		Category: "agent-control",
		Rules: []guardrail.RuleDefYAML{{
			ID:         "AC-HOOK-DENY",
			Pattern:    `agent-control-hook-marker`,
			Title:      "AgentControl hook marker",
			Severity:   "HIGH",
			Confidence: 1,
		}},
	}}}
	ApplyRulePackOverridesForSource(pack, guardrail.RegexSourceAgentControl)

	cfg := &config.Config{PolicyDir: policyDir}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "codex"
	cfg.Guardrail.RegexSource = config.RegexSourceAgentControl
	api := &APIServer{scannerCfg: cfg}
	response := api.evaluateCodexHook(t.Context(), codexHookRequest{
		HookEventName: "PreToolUse",
		ToolName:      "Bash",
		ToolInput:     map[string]interface{}{"command": "printf '%s\\n' 'agent-control-hook-marker'"},
		CWD:           "/repo",
	})

	if response.Action != guardrailActionBlock || response.RawAction != guardrailActionBlock ||
		response.WouldBlock || response.Severity != "HIGH" ||
		!findingStringHasRuleID(response.Findings, "AC-HOOK-DENY") {
		t.Fatalf("AgentControl hook response = %+v, want enforced HIGH/block with managed finding", response)
	}
	decision, _ := response.CodexOutput["hookSpecificOutput"].(map[string]interface{})
	if decision["permissionDecision"] != "deny" {
		t.Fatalf("Codex hook output = %+v, want permissionDecision=deny", response.CodexOutput)
	}
}

func TestLoadValidatedRulePackForSourceUsesAgentControlOverlay(t *testing.T) {
	overlay := t.TempDir()
	rulesDir := filepath.Join(overlay, "rules")
	if err := os.Mkdir(rulesDir, 0o700); err != nil {
		t.Fatal(err)
	}
	contents := []byte("version: 1\ncategory: agent-control\nrules:\n  - id: AC-OVERLAY\n    pattern: managed-overlay-marker\n    title: Managed overlay marker\n    severity: HIGH\n    confidence: 1\n    tags: [integration-test]\n")
	if err := os.WriteFile(filepath.Join(rulesDir, "agent-control.yaml"), contents, 0o600); err != nil {
		t.Fatal(err)
	}

	rp, err := loadValidatedRulePackForSource(
		guardrail.NewRulePackCache(),
		"",
		[]string{overlay},
		guardrail.RegexSourceAgentControl,
		"test",
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(rp.RuleFiles) != 1 || rp.RuleFiles[0].Category != "agent-control" {
		t.Fatalf("loaded rule files = %+v", rp.RuleFiles)
	}
	if rp.LocalPatterns != nil {
		t.Fatal("agent-control source retained local patterns")
	}
}

func TestActiveManagedRulePackStatusReportsSourceAndOnlyActiveArtifact(t *testing.T) {
	overlay := t.TempDir()
	rules := filepath.Join(overlay, "rules")
	if err := os.Mkdir(rules, 0o700); err != nil {
		t.Fatal(err)
	}
	contents := []byte("version: 1\ncategory: agent-control\nrules:\n  - id: AC-ONE\n    pattern: central\n    title: Central\n    severity: HIGH\n    confidence: 1\n    tags: []\n")
	if err := os.WriteFile(filepath.Join(rules, "agent-control.yaml"), contents, 0o600); err != nil {
		t.Fatal(err)
	}

	local, err := activeManagedRulePackStatus(&config.GuardrailConfig{
		RegexSource:         config.RegexSourceLocal,
		RulePackOverlayDirs: []string{overlay},
	})
	if err != nil {
		t.Fatal(err)
	}
	if local.RegexSource != config.RegexSourceLocal || local.Present || local.ArtifactDigest != "" {
		t.Fatalf("local status = %+v", local)
	}

	hybrid, err := activeManagedRulePackStatus(&config.GuardrailConfig{
		RegexSource:         config.RegexSourceHybrid,
		RulePackOverlayDirs: []string{overlay},
	})
	if err != nil {
		t.Fatal(err)
	}
	if hybrid.RegexSource != config.RegexSourceHybrid || !hybrid.Present || hybrid.ArtifactDigest == "" {
		t.Fatalf("hybrid status = %+v", hybrid)
	}
}
