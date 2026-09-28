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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const redirectReductionMarker = "dccert-block-marker"

// installRedirectReductionRules publishes a connector generation with
// certification-style command rules: CRITICAL expressions over argv.
func installRedirectReductionRules(t *testing.T, connector string, rules ...PatternRule) {
	t.Helper()
	ruleCategoriesMu.Lock()
	savedCategories, hadCategories := connectorRuleCategories[connector]
	savedGeneration, hadGeneration := connectorRuleGenerations[connector]
	ruleCategoriesMu.Unlock()
	t.Cleanup(func() {
		ruleCategoriesMu.Lock()
		if hadCategories {
			connectorRuleCategories[connector] = savedCategories
		} else {
			delete(connectorRuleCategories, connector)
		}
		if hadGeneration {
			connectorRuleGenerations[connector] = savedGeneration
		} else {
			delete(connectorRuleGenerations, connector)
		}
		ruleCategoriesMu.Unlock()
	})
	generation, err := compileRulePackGeneration([]ruleCategory{{
		Name:  "cert-marker",
		Rules: rules,
	}})
	if err != nil {
		t.Fatal(err)
	}
	publishConnectorRulePackOverrides(connector, generation)
}

func redirectReductionRule(id, pattern, expression string) PatternRule {
	return PatternRule{
		ID:           id,
		Pattern:      regexp.MustCompile(pattern),
		Expression:   expression,
		ToolCallOnly: true,
		Title:        "Certification marker (" + id + ")",
		Severity:     "CRITICAL",
		Confidence:   1,
	}
}

func TestTrustedActionBlocksCommandRuleWithRuntimeExpandedRedirectTarget(t *testing.T) {
	const connector = "redirect-reduction-test"
	argvMarker := `f.commands.exists(c, c.argv.exists(a, a == "` + redirectReductionMarker + `"))`
	installRedirectReductionRules(t, connector,
		// The certification rule: an argv expression with a regex fallback.
		redirectReductionRule("CERT-MARKER-BLOCK", redirectReductionMarker, argvMarker),
		// A semantic-only rule has no fallback evidence at all.
		redirectReductionRule("CERT-MARKER-SEMANTIC", `a^`, argvMarker),
		// Negation that does not read redirects keeps the reduced match.
		redirectReductionRule(
			"CERT-MARKER-NOT-DRY-RUN",
			redirectReductionMarker,
			`f.commands.exists(c, c.argv.exists(a, a == "`+redirectReductionMarker+`") && `+
				`!c.argv.exists(a, a == "--dry-run"))`,
		),
		// A match that more redirects could undo must not count on the view.
		redirectReductionRule(
			"CERT-MARKER-NO-STDOUT-REDIRECT",
			redirectReductionMarker,
			argvMarker+` && !f.commands.exists(c, c.redirects.exists(r, r.fd == 1))`,
		),
	)

	const (
		blocks        = "block"
		detectionOnly = "detection-only"
		absent        = "absent"
	)
	tests := []struct {
		name    string
		command string
		want    map[string]string
	}{
		{
			// Complete facts: the negated rule's non-match is decisive.
			name:    "absolute target",
			command: "echo " + redirectReductionMarker + " > /home/alice/dccert-x.txt",
			want: map[string]string{
				"CERT-MARKER-BLOCK":              blocks,
				"CERT-MARKER-SEMANTIC":           blocks,
				"CERT-MARKER-NOT-DRY-RUN":        blocks,
				"CERT-MARKER-NO-STDOUT-REDIRECT": absent,
			},
		},
		{
			name:    "tilde target",
			command: "echo " + redirectReductionMarker + " > ~/dccert-x.txt",
			want: map[string]string{
				"CERT-MARKER-BLOCK":              blocks,
				"CERT-MARKER-SEMANTIC":           blocks,
				"CERT-MARKER-NOT-DRY-RUN":        blocks,
				"CERT-MARKER-NO-STDOUT-REDIRECT": detectionOnly,
			},
		},
		{
			name:    "HOME target",
			command: "echo " + redirectReductionMarker + " > $HOME/dccert-x.txt",
			want: map[string]string{
				"CERT-MARKER-BLOCK":              blocks,
				"CERT-MARKER-SEMANTIC":           blocks,
				"CERT-MARKER-NOT-DRY-RUN":        blocks,
				"CERT-MARKER-NO-STDOUT-REDIRECT": detectionOnly,
			},
		},
		{
			name:    "no redirect",
			command: "echo " + redirectReductionMarker,
			want: map[string]string{
				"CERT-MARKER-BLOCK":              blocks,
				"CERT-MARKER-SEMANTIC":           blocks,
				"CERT-MARKER-NOT-DRY-RUN":        blocks,
				"CERT-MARKER-NO-STDOUT-REDIRECT": blocks,
			},
		},
		{
			name:    "tilde target without the marker",
			command: "echo dccert-allowed > ~/dccert-x.txt",
			want: map[string]string{
				"CERT-MARKER-BLOCK":              absent,
				"CERT-MARKER-SEMANTIC":           absent,
				"CERT-MARKER-NOT-DRY-RUN":        absent,
				"CERT-MARKER-NO-STDOUT-REDIRECT": absent,
			},
		},
		{
			// An expanding argument is not reduced: the argv is not static.
			name:    "expanding argument",
			command: "echo " + redirectReductionMarker + " $SUFFIX > ~/dccert-x.txt",
			want: map[string]string{
				"CERT-MARKER-BLOCK":              detectionOnly,
				"CERT-MARKER-SEMANTIC":           absent,
				"CERT-MARKER-NOT-DRY-RUN":        detectionOnly,
				"CERT-MARKER-NO-STDOUT-REDIRECT": detectionOnly,
			},
		},
		{
			// A chained command might not run, so it is not reduced either.
			name:    "chained command",
			command: "cd /tmp && echo " + redirectReductionMarker + " > ~/dccert-x.txt",
			want: map[string]string{
				"CERT-MARKER-BLOCK":              detectionOnly,
				"CERT-MARKER-SEMANTIC":           absent,
				"CERT-MARKER-NOT-DRY-RUN":        detectionOnly,
				"CERT-MARKER-NO-STDOUT-REDIRECT": detectionOnly,
			},
		},
	}
	for _, test := range tests {
		for _, home := range []string{"/home/alice", ""} {
			t.Run(test.name+"/home="+home, func(t *testing.T) {
				var recorded actionfacts.Facts
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{
					Input: actionfacts.Input{
						Tool:        "shell",
						Command:     test.command,
						CWD:         "/home/alice/project",
						ActiveHome:  home,
						DialectHint: actionfacts.DialectPOSIX,
					},
					LegacyText:         test.command,
					Connector:          connector,
					EnforcementCapable: true,
					record: func(facts actionfacts.Facts, _ []RuleFinding) {
						recorded = facts
					},
				})
				for ruleID, want := range test.want {
					finding := findingWithID(findings, ruleID)
					got := absent
					if finding != nil {
						got = detectionOnly
						if finding.contributesToEnforcement() {
							got = blocks
						}
					}
					if got != want {
						t.Errorf("%s = %s, want %s; findings=%v", ruleID, got, want, FindingStrings(findings))
					}
				}
				verdict := buildVerdict(findings, "tool_call")
				wantAction := guardrailActionAllow
				if test.want["CERT-MARKER-BLOCK"] == blocks {
					wantAction = guardrailActionBlock
				}
				if verdict.Action != wantAction {
					t.Errorf("verdict = %q, want %q; findings=%v", verdict.Action, wantAction, FindingStrings(findings))
				}
				// The audit keeps the facts of the whole action, not the view.
				if recorded.Commands == nil {
					t.Fatal("dispatch did not record the action facts")
				}
				for _, command := range recorded.Commands {
					for _, redirect := range command.Redirects {
						if redirect.Expands && recorded.Authoritative() {
							t.Fatalf("recorded facts were replaced by the reduced view: %+v", recorded.Parse)
						}
					}
				}
			})
		}
	}
}
