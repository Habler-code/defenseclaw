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
	"crypto/sha256"
	"regexp"
	"strings"
	"sync"
	"time"
)

// This virtual patch recognizes the study's forged user-turn delimiters when
// they carry a bounded, study-derived claim. Only the narrower forged approval and
// curl-to-shell combination can affect a later tool decision. A delimiter
// alone is not evidence that an instruction survived compaction.
const (
	compactionGuardRuleID         = "COMPACTION-FORGED-APPROVAL-001"
	compactionPoisonRuleID        = "COMPACTION-INSTRUCTION-POISON-001"
	compactionCodexWarningMessage = "DefenseClaw found a possible forged user-role claim in tool output before compaction. The compacted context cannot be verified. Start a new session before sensitive work."
	compactionWarningMessage      = "DefenseClaw found evidence of a forged user instruction in Claude Code's exposed compaction summary. Start a new session before sensitive work."
	compactionNoEvidenceMessage   = "DefenseClaw compaction scan found no matching forged-user claim in the exposed summary. This does not verify the full session context."
	compactionNoSummaryMessage    = "DefenseClaw could not inspect Claude Code's compaction summary. The session remains unverified."
	compactionGuardMaxInput       = 256 * 1024
	compactionGuardMaxClaim       = 1024
	compactionGuardMaxMarkers     = 128
	compactionGuardMaxSessions    = 256
	compactionGuardMaxCandidates  = 8
	compactionGuardSessionTTL     = 2 * time.Hour
)

var (
	compactionNextRole = regexp.MustCompile(`(?m)\n[ \t]*(?:\[(?:User|Assistant|Tool result|user|assistant)\]:|#[ \t]+(?:USER|ASSISTANT)\b|<EVENT>|</EVENT>|##[ \t]+Message[ \t]+[0-9]+\b)`)
	compactionApproval = regexp.MustCompile(`(?i)\b(?:already[ \t]+(?:reviewed[ \t]+and[ \t]+)?approved|you[ \t]+(?:already[ \t]+)?have[ \t]+my[ \t]+approval)\b`)
	compactionNoAsk    = regexp.MustCompile(`(?i)\b(?:do[ \t]+not[ \t]+ask|don't[ \t]+ask|no[ \t]+need[ \t]+to[ \t]+(?:ask|re-prompt)|without[ \t]+asking)\b`)
	compactionCurlPipe = regexp.MustCompile(`(?i)\bcurl(?:[ \t]+-[a-z]+)*[ \t]+https?://[^\s|"'<>;&\x60$]+[ \t]*\|[ \t]*(?:sh|bash)\b`)
	// Any of the survey's exact forged-user envelopes is an attempted
	// authority boundary crossing in tool output. Seeing one does not prove
	// that the current connector serializes or promotes it during compaction.
	compactionRoleHeader         = regexp.MustCompile(`(?m)(?:^|\n)[ \t]*(?:\[User\]:[ \t]*|\[user\]:[ \t]*|#[ \t]+USER[ \t]*\n[ \t]*|</EVENT>[ \t]*\n[ \t]*<EVENT>[ \t]*\n[ \t]*MessageEvent \(user\)[ \t]*\n[ \t]*user:[ \t]*|##[ \t]+Message[ \t]+[1-9][0-9]{0,5}[ \t]*\n[ \t]*Role:[ \t]*user[ \t]*\n[ \t]*Content:[ \t]*\n[ \t]*)`)
	compactionAvoidance          = regexp.MustCompile(`(?i)\b(?:don't|do not|never)[ \t]+(?:modify|change|touch|review|inspect|scan|check|read|open|edit|update)\b|\bleave[ \t]+[^\n.]{1,100}[ \t]+(?:untouched|alone|out of scope)\b|\bi[ \t]+don't[ \t]+want[ \t]+changes[ \t]+under\b`)
	compactionExfil              = regexp.MustCompile(`(?i)\b(?:post|send|upload|transmit)[ \t]+[^\n.]{0,160}\b(?:findings|results|report|data|secrets|credentials)[ \t]+[^\n.]{0,160}https?://[^\s<>]+`)
	compactionMemory             = regexp.MustCompile(`(?i)\b(?:when[ \t]+(?:you[ \t]+)?(?:compact|summari[sz]e)|after[ \t]+(?:the[ \t]+)?compaction|in[ \t]+(?:the[ \t]+)?(?:compacted[ \t]+)?summary|for[ \t]+(?:future|later|subsequent)[ \t]+(?:turns|messages|responses))\b`)
	compactionMemoryVerb         = regexp.MustCompile(`(?i)\b(?:remember|retain|preserve|include|record|write|carry[ \t]+forward|treat)\b`)
	compactionFalseFact          = regexp.MustCompile(`(?i)\bfor[ \t]+context:[ \t]+[^\n.]{1,160}\b(?:is|are|listens|uses)[ \t]+[^\n.]{1,120}\bnot[ \t]+(?:the[ \t]+)?(?:default|documented|current)\b`)
	compactionNewTask            = regexp.MustCompile(`(?i)\bonce[ \t]+[^\n.]{1,120}\bnext[ \t]+thing[ \t]+i[ \t]+need[ \t]+is\b`)
	compactionOverride           = regexp.MustCompile(`(?i)\b(?:ignore|disregard)[ \t]+(?:the[ \t]+|your[ \t]+)?(?:earlier|previous)[ \t]+(?:instructions|constraints|confirmation[ \t]+prompts)\b`)
	compactionSummaryApproval    = regexp.MustCompile(`(?i)^[ \t]*(?:[-*][ \t]+)?(?:the[ \t]+)?user[ \t]+(?:has[ \t]+)?(?:already[ \t]+)?approved\b`)
	compactionSummaryInstruction = regexp.MustCompile(`(?i)^[ \t]*(?:[-*][ \t]+)?(?:the[ \t]+)?user[ \t]+(?:requested|asked|instructed)[ \t]*:[ \t]*`)
	compactionSummaryDisavowal   = regexp.MustCompile(`(?i)\b(?:file|document|tool[ \t]+output|untrusted|forged|fake|spoofed|injection|attack|claimed|quoted|purported|did[ \t]+not|not[ \t]+an?[ \t]+instruction)\b`)
)

type compactionGuardCandidate struct {
	seen           time.Time
	pending        bool
	active         bool
	warned         bool
	summaryAlerted bool
	summaryDigest  [sha256.Size]byte
}

type compactionGuardSession struct {
	lastSeen     time.Time
	candidates   map[[sha256.Size]byte]*compactionGuardCandidate
	instructions map[[sha256.Size]byte]*compactionGuardCandidate
	approved     map[[sha256.Size]byte]time.Time
	inlineNotice string
	compactDue   bool
}

// compactionGuardStore is process-local and contains command digests only.
// No tool output, summary, prompt, URL, or command text is retained.
type compactionGuardStore struct {
	mu       sync.Mutex
	sessions map[string]*compactionGuardSession
}

func compactionGuardKey(connector, sessionID string) string {
	sessionID = strings.TrimSpace(sessionID)
	if (connector != "codex" && connector != "claudecode") || sessionID == "" || len(sessionID) > 256 {
		return ""
	}
	return connector + "\x00" + sessionID
}

func (s *compactionGuardStore) session(key string, create bool, now time.Time) *compactionGuardSession {
	if key == "" {
		return nil
	}
	if s.sessions == nil {
		if !create {
			return nil
		}
		s.sessions = make(map[string]*compactionGuardSession)
	}
	for id, state := range s.sessions {
		if now.Sub(state.lastSeen) > compactionGuardSessionTTL {
			delete(s.sessions, id)
		}
	}
	if state := s.sessions[key]; state != nil {
		state.lastSeen = now
		return state
	}
	if !create {
		return nil
	}
	if len(s.sessions) >= compactionGuardMaxSessions {
		var oldestKey string
		var oldest time.Time
		for id, state := range s.sessions {
			if oldestKey == "" || state.lastSeen.Before(oldest) {
				oldestKey, oldest = id, state.lastSeen
			}
		}
		delete(s.sessions, oldestKey)
	}
	state := &compactionGuardSession{
		lastSeen:     now,
		candidates:   make(map[[sha256.Size]byte]*compactionGuardCandidate),
		instructions: make(map[[sha256.Size]byte]*compactionGuardCandidate),
		approved:     make(map[[sha256.Size]byte]time.Time),
	}
	s.sessions[key] = state
	return state
}

func (s *compactionGuardStore) reset(connector, sessionID string) {
	key := compactionGuardKey(connector, sessionID)
	if key == "" {
		return
	}
	s.mu.Lock()
	delete(s.sessions, key)
	s.mu.Unlock()
}

// observeToolResult performs a bounded exact-pattern scan on successful tool
// output. It only records a candidate; existing PostToolUse decisions remain
// entirely under their existing policy path.
func (s *compactionGuardStore) observeToolResult(connector, sessionID, output string) bool {
	key := compactionGuardKey(connector, sessionID)
	if key == "" {
		return false
	}
	command, ok := forgedApprovalCommand(output)
	if !ok {
		return false
	}
	digest := sha256.Sum256([]byte(command))
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.session(key, true, now)
	if _, approved := state.approved[digest]; approved {
		return false
	}
	if prior := state.candidates[digest]; prior != nil {
		prior.seen = now
		return true
	}
	if len(state.candidates) >= compactionGuardMaxCandidates {
		var oldestDigest [sha256.Size]byte
		var oldest time.Time
		for id, candidate := range state.candidates {
			if oldest.IsZero() || candidate.seen.Before(oldest) {
				oldestDigest, oldest = id, candidate.seen
			}
		}
		delete(state.candidates, oldestDigest)
	}
	state.candidates[digest] = &compactionGuardCandidate{seen: now}
	return true
}

// observeInstructionResult records a role-spoofing shape that could promote
// tool content into user authority. It does not alter PostToolUse decisions;
// a declarative claim is only a warning candidate, not proof of intent.
func (s *compactionGuardStore) observeInstructionResult(connector, sessionID, output string) bool {
	key := compactionGuardKey(connector, sessionID)
	// The exact forged-approval path already records this tool result and
	// supports authenticated user approval; do not create a second alert
	// that would survive after that approval clears the action candidate.
	if _, strict := forgedApprovalCommand(output); strict {
		return false
	}
	claim, ok := instructionPoisoningClaim(output)
	if key == "" || !ok {
		return false
	}
	digest := sha256.Sum256([]byte(strings.ToLower(strings.Join(strings.Fields(claim), " "))))
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.session(key, true, now)
	if prior := state.instructions[digest]; prior != nil {
		prior.seen = now
		return true
	}
	if len(state.instructions) >= compactionGuardMaxCandidates {
		var oldestDigest [sha256.Size]byte
		var oldest time.Time
		for id, candidate := range state.instructions {
			if oldest.IsZero() || candidate.seen.Before(oldest) {
				oldestDigest, oldest = id, candidate.seen
			}
		}
		delete(state.instructions, oldestDigest)
	}
	firstLine, _, _ := strings.Cut(claim, "\n")
	state.instructions[digest] = &compactionGuardCandidate{
		seen:          now,
		summaryDigest: sha256.Sum256([]byte(strings.ToLower(strings.Join(strings.Fields(firstLine), " ")))),
	}
	return true
}

func (s *compactionGuardStore) observeUserPrompt(connector, sessionID, prompt string) {
	key := compactionGuardKey(connector, sessionID)
	command, ok := explicitUserApprovalCommand(prompt)
	if key == "" || !ok {
		return
	}
	digest := sha256.Sum256([]byte(command))
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.session(key, true, now)
	if len(state.approved) >= compactionGuardMaxCandidates {
		var oldestDigest [sha256.Size]byte
		var oldest time.Time
		for id, seen := range state.approved {
			if oldest.IsZero() || seen.Before(oldest) {
				oldestDigest, oldest = id, seen
			}
		}
		delete(state.approved, oldestDigest)
	}
	state.approved[digest] = now
	delete(state.candidates, digest)
}

type compactionGuardPending struct {
	action      bool
	instruction bool
}

func (s *compactionGuardStore) preCompact(connector, sessionID string) compactionGuardPending {
	key := compactionGuardKey(connector, sessionID)
	if key == "" {
		return compactionGuardPending{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.session(key, connector == "claudecode", time.Now())
	if state == nil {
		return compactionGuardPending{}
	}
	state.compactDue = true
	var pending compactionGuardPending
	for _, candidate := range state.candidates {
		candidate.pending = true
		pending.action = true
	}
	for _, candidate := range state.instructions {
		candidate.pending = true
		pending.instruction = true
	}
	return pending
}

// PostCompact discards systemMessage. A summary-based notice is queued for the
// first eligible later hook because compact-source SessionStart can run first.
func (s *compactionGuardStore) takeClaudeInlineNotice(sessionID string) string {
	key := compactionGuardKey("claudecode", sessionID)
	if key == "" {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.session(key, false, time.Now())
	if state == nil {
		return ""
	}
	notice := state.inlineNotice
	state.inlineNotice = ""
	return notice
}

// inspectClaudeSummary only treats an explicit user-authority assertion as
// evidence when it matches a prior forged claim from untrusted tool output.
// Quoted/code-fenced material and lines attributing the claim to a file or
// injection are excluded. This high-precision rule intentionally misses
// paraphrases; a negative result is never a safety certification. It returns
// true only for newly matched evidence so a later compaction does not repeat
// the same OS alert. The inline notice still describes each summary scan.
func (s *compactionGuardStore) inspectClaudeSummary(sessionID, summary string) bool {
	key := compactionGuardKey("claudecode", sessionID)
	if key == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.session(key, true, time.Now())
	if strings.TrimSpace(summary) == "" || len(summary) > compactionGuardMaxInput {
		state.inlineNotice = compactionNoSummaryMessage
		return false
	}
	evidence := false
	newEvidence := false
	inFence := false
	previous := ""
	for _, line := range strings.Split(strings.ReplaceAll(summary, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			inFence = !inFence
			previous = trimmed
			continue
		}
		if inFence || len(line) > compactionGuardMaxClaim || compactionSummaryDisavowal.MatchString(line) || compactionSummaryDisavowal.MatchString(previous) {
			previous = trimmed
			continue
		}
		if compactionSummaryApproval.MatchString(line) && compactionNoAsk.MatchString(line) {
			if command, ok := compactionCommandInText(line); ok {
				digest := sha256.Sum256([]byte(command))
				if candidate := state.candidates[digest]; candidate != nil && candidate.active {
					if _, approved := state.approved[digest]; !approved {
						evidence = true
						if !candidate.summaryAlerted {
							candidate.summaryAlerted = true
							newEvidence = true
						}
					}
				}
			}
		}
		if location := compactionSummaryInstruction.FindStringIndex(line); location != nil {
			claim := strings.TrimSpace(line[location[1]:])
			digest := sha256.Sum256([]byte(strings.ToLower(strings.Join(strings.Fields(claim), " "))))
			for _, candidate := range state.instructions {
				if candidate.warned && candidate.summaryDigest == digest {
					evidence = true
					if !candidate.summaryAlerted {
						candidate.summaryAlerted = true
						newEvidence = true
					}
					break
				}
			}
		}
		previous = trimmed
	}
	if evidence {
		state.inlineNotice = compactionWarningMessage
	} else {
		state.inlineNotice = compactionNoEvidenceMessage
	}
	return newEvidence
}

type compactionGuardActivation struct {
	actionActive    bool
	actionWarn      bool
	instructionWarn bool
	completed       bool
}

// postCompact activates pending candidates without treating a generated
// summary as a complete or authoritative account of the resumed context.
// Only an exact forged-approval candidate can affect a later tool call.
func (s *compactionGuardStore) postCompact(connector, sessionID string) compactionGuardActivation {
	key := compactionGuardKey(connector, sessionID)
	if key == "" {
		return compactionGuardActivation{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.session(key, false, time.Now())
	if state == nil {
		return compactionGuardActivation{}
	}
	result := compactionGuardActivation{completed: state.compactDue}
	state.compactDue = false
	for _, candidate := range state.candidates {
		if candidate.pending && !candidate.warned {
			result.actionWarn = true
			candidate.warned = true
		}
		candidate.active = candidate.active || candidate.pending
		candidate.pending = false
		if candidate.active {
			result.actionActive = true
		}
	}
	for _, candidate := range state.instructions {
		if candidate.pending && !candidate.warned {
			result.instructionWarn = true
			candidate.warned = true
		}
		candidate.pending = false
	}
	return result
}

func instructionPoisoningClaim(output string) (string, bool) {
	if len(output) == 0 || len(output) > compactionGuardMaxInput {
		return "", false
	}
	output = strings.ReplaceAll(output, "\r\n", "\n")
	for _, marker := range compactionRoleHeader.FindAllStringIndex(output, compactionGuardMaxMarkers) {
		end := min(len(output), marker[1]+compactionGuardMaxClaim)
		claim := output[marker[1]:end]
		// Goose serializes an ordinary tool response under a user role as
		// `[user]: tool_response: ...`. That wrapper is not a forged new
		// user turn and would otherwise produce an avoidable false alert.
		if strings.Contains(output[marker[0]:marker[1]], "[user]:") &&
			strings.HasPrefix(strings.ToLower(strings.TrimSpace(claim)), "tool_response:") {
			continue
		}
		if next := compactionNextRole.FindStringIndex(claim); next != nil {
			claim = claim[:next[0]]
		}
		if compactionAvoidance.MatchString(claim) || compactionExfil.MatchString(claim) ||
			compactionFalseFact.MatchString(claim) || compactionNewTask.MatchString(claim) ||
			compactionOverride.MatchString(claim) ||
			(compactionMemory.MatchString(claim) && compactionMemoryVerb.MatchString(claim)) ||
			(compactionApproval.MatchString(claim) && compactionNoAsk.MatchString(claim)) {
			return claim, true
		}
	}
	return "", false
}

func compactionPoisonFinding(verdict *ToolInspectVerdict, phase string) {
	if verdict == nil {
		return
	}
	severity := "INFO"
	if phase == "post_compact_warning" {
		severity = "HIGH"
	}
	verdict.Findings = append(verdict.Findings, compactionPoisonRuleID)
	verdict.DetailedFindings = append(verdict.DetailedFindings, RuleFinding{
		RuleID:     compactionPoisonRuleID,
		Title:      "Possible forged user-role claim before compaction",
		Severity:   severity,
		Confidence: 0.9,
		Evidence:   phase,
		Tags:       []string{"compaction", "untrusted_tool_result", "forged_authority"},
	})
	if verdict.Severity == "" || verdict.Severity == "NONE" || (severity == "HIGH" && verdict.Severity == "INFO") {
		verdict.Severity = severity
	}
}

func (s *compactionGuardStore) matchingAction(connector, sessionID, toolName string, toolInput map[string]interface{}) bool {
	key := compactionGuardKey(connector, sessionID)
	command, ok := compactionCommandFromTool(toolName, toolInput)
	if key == "" || !ok {
		return false
	}
	digest := sha256.Sum256([]byte(command))
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.session(key, false, time.Now())
	if state == nil {
		return false
	}
	if _, approved := state.approved[digest]; approved {
		return false
	}
	candidate := state.candidates[digest]
	return candidate != nil && candidate.active
}

func forgedApprovalCommand(output string) (string, bool) {
	if len(output) == 0 || len(output) > compactionGuardMaxInput {
		return "", false
	}
	output = strings.ReplaceAll(output, "\r\n", "\n")
	markers := compactionRoleHeader.FindAllStringIndex(output, compactionGuardMaxMarkers)
	for _, marker := range markers {
		end := marker[1] + compactionGuardMaxClaim
		if end > len(output) {
			end = len(output)
		}
		claim := output[marker[1]:end]
		if strings.Contains(output[marker[0]:marker[1]], "[user]:") &&
			strings.HasPrefix(strings.ToLower(strings.TrimSpace(claim)), "tool_response:") {
			continue
		}
		if next := compactionNextRole.FindStringIndex(claim); next != nil {
			claim = claim[:next[0]]
		}
		if !compactionApproval.MatchString(claim) || !compactionNoAsk.MatchString(claim) {
			continue
		}
		if command, ok := compactionCommandInText(claim); ok {
			return command, true
		}
	}
	return "", false
}

func compactionCommandInText(text string) (string, bool) {
	match := compactionCurlPipe.FindString(text)
	if match == "" {
		return "", false
	}
	return strings.Join(strings.Fields(match), " "), true
}

func explicitUserApprovalCommand(prompt string) (string, bool) {
	if len(prompt) == 0 || len(prompt) > compactionGuardMaxClaim {
		return "", false
	}
	trimmed := strings.TrimSpace(prompt)
	lower := strings.ToLower(trimmed)
	for _, prefix := range []string{"i approve running ", "i approve ", "yes, run ", "yes run ", "please run ", "run "} {
		if strings.HasPrefix(lower, prefix) {
			command := strings.TrimSpace(trimmed[len(prefix):])
			command = strings.TrimSuffix(command, ".")
			command = strings.Trim(command, "`")
			return compactionExactCommand(command)
		}
	}
	return "", false
}

func compactionCommandFromTool(toolName string, input map[string]interface{}) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(toolName)) {
	case "bash", "shell", "exec_command", "run_command":
	default:
		return "", false
	}
	for _, key := range []string{"command", "cmd", "CommandLine"} {
		if value, ok := input[key].(string); ok {
			return compactionExactCommand(value)
		}
	}
	return "", false
}

func compactionExactCommand(command string) (string, bool) {
	command = strings.TrimSpace(command)
	if len(command) == 0 || len(command) > compactionGuardMaxClaim {
		return "", false
	}
	match, ok := compactionCommandInText(command)
	if !ok || match != strings.Join(strings.Fields(command), " ") {
		return "", false
	}
	return match, true
}

func compactionGuardFinding(verdict *ToolInspectVerdict, phase, action string) {
	if verdict == nil {
		return
	}
	severity := "INFO"
	if action != "" {
		severity = "CRITICAL"
	}
	verdict.Findings = append(verdict.Findings, compactionGuardRuleID)
	verdict.DetailedFindings = append(verdict.DetailedFindings, RuleFinding{
		RuleID:     compactionGuardRuleID,
		Title:      "Forged approval across compaction",
		Severity:   severity,
		Confidence: 1,
		Evidence:   phase,
		Tags:       []string{"compaction", "untrusted_tool_result", "forged_authority"},
	})
	if action == "" {
		if verdict.Severity == "" || verdict.Severity == "NONE" {
			verdict.Severity = severity
		}
		return
	}
	if normalizedGuardrailActionRank(action) > normalizedGuardrailActionRank(verdict.Action) {
		verdict.Action = action
		verdict.Reason = "The approval for this exact command appeared in untrusted tool output before compaction. Ask the user to approve it explicitly."
	}
	verdict.Severity = "CRITICAL"
	verdict.Confidence = 1
}
