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

package enterprisehooks

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"

	"github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable"
)

// On macOS and Linux Codex reads administrator requirements from
// /etc/codex/requirements.toml. When the requirements pin
// [features] hooks = true, Codex keeps hooks enabled whatever the user
// configures ([features] hooks in config.toml, -c features.hooks, or
// --disable hooks). DefenseClaw's macOS Codex hooks are user-level, so the
// managed guardian publishes only that pin; it never sets
// allow_managed_hooks_only there, which would stop the user-level hooks.
//
// The requirements file can be administrator-authored, so DefenseClaw never
// re-marshals it. It inserts one tagged line into an existing [features]
// table, or appends one delimited region, and removes exactly those bytes
// again. Every edit is re-parsed and must equal the expected model; an
// unfamiliar layout fails closed without changing the file. The markers match
// the Windows requirements editor.
const (
	codexRequirementsPinLineMarker  = "# managed by DefenseClaw"
	codexRequirementsPinRegionBegin = "# BEGIN DefenseClaw managed hooks (generated; do not edit inside this block)"
	codexRequirementsPinRegionEnd   = "# END DefenseClaw managed hooks"

	// codexRequirementsPinLimit bounds the requirements document DefenseClaw
	// reads and rewrites.
	codexRequirementsPinLimit = 2 << 20
)

// Codex requirements hooks-pin states.
const (
	// CodexRequirementsPinAbsent means the requirements do not pin hooks on.
	CodexRequirementsPinAbsent = "absent"
	// CodexRequirementsPinOwned means DefenseClaw's tagged pin is present.
	CodexRequirementsPinOwned = "owned"
	// CodexRequirementsPinAdministrator means the administrator's own
	// requirements already pin [features] hooks = true; DefenseClaw leaves it
	// alone and never removes it.
	CodexRequirementsPinAdministrator = "administrator"
)

// CodexRequirementsPinResult reports one inspect, ensure, or remove call.
type CodexRequirementsPinResult struct {
	Path        string `json:"path"`
	State       string `json:"state"`
	Changed     bool   `json:"changed"`
	RemovedFile bool   `json:"removed_file,omitempty"`
}

var (
	errCodexRequirementsPinUneditable = errors.New(
		"the Codex requirements layout cannot be edited automatically; add [features] hooks = true to the requirements file",
	)
	errCodexRequirementsPinUnremovable = errors.New(
		"DefenseClaw's hooks pin cannot be removed automatically from this Codex requirements layout; " +
			"delete the lines marked '" + codexRequirementsPinLineMarker + "' or the DefenseClaw managed hooks block from the requirements file",
	)
)

func parseCodexRequirementsPinModel(raw []byte) (map[string]interface{}, error) {
	model := map[string]interface{}{}
	if len(bytes.TrimSpace(raw)) == 0 {
		return model, nil
	}
	if err := toml.Unmarshal(raw, &model); err != nil {
		return nil, fmt.Errorf("parse Codex requirements: %w", err)
	}
	return model, nil
}

// codexRequirementsFeaturesHooks returns the [features] hooks value. It fails
// when features is not a table, or when hooks is present but not true: an
// administrator requirement that turns hooks off cannot be overridden by
// DefenseClaw and must be resolved by the administrator.
func codexRequirementsFeaturesHooks(model map[string]interface{}) (present bool, err error) {
	rawFeatures, exists := model["features"]
	if !exists {
		return false, nil
	}
	features, ok := rawFeatures.(map[string]interface{})
	if !ok {
		return false, errors.New("Codex requirements [features] is not a table")
	}
	rawHooks, exists := features["hooks"]
	if !exists {
		return false, nil
	}
	if enabled, ok := rawHooks.(bool); !ok || !enabled {
		return false, fmt.Errorf(
			"Codex requirements set [features] hooks = %v, which disables DefenseClaw's Codex hooks; set it to true or remove it",
			rawHooks,
		)
	}
	return true, nil
}

// inspectCodexRequirementsPin classifies a requirements document.
func inspectCodexRequirementsPin(raw []byte) (string, error) {
	model, err := parseCodexRequirementsPinModel(raw)
	if err != nil {
		return "", err
	}
	present, err := codexRequirementsFeaturesHooks(model)
	if err != nil {
		return "", err
	}
	if !present {
		return CodexRequirementsPinAbsent, nil
	}
	if codexRequirementsPinHasOwnedBytes(raw) {
		return CodexRequirementsPinOwned, nil
	}
	return CodexRequirementsPinAdministrator, nil
}

// renderCodexRequirementsPin returns raw with DefenseClaw's hooks pin added.
// changed is false when hooks are already pinned on, by the administrator or
// by an earlier DefenseClaw edit.
func renderCodexRequirementsPin(raw []byte) (rendered []byte, changed bool, err error) {
	model, err := parseCodexRequirementsPinModel(raw)
	if err != nil {
		return nil, false, err
	}
	present, err := codexRequirementsFeaturesHooks(model)
	if err != nil {
		return nil, false, err
	}
	if present {
		return raw, false, nil
	}
	newline := codexRequirementsPinNewline(raw)
	layout, err := scanCodexRequirementsPinLayout(raw)
	if err != nil {
		return nil, false, err
	}
	switch {
	case layout.featuresInline:
		return nil, false, errCodexRequirementsPinUneditable
	case layout.featuresHeaderLineEnd >= 0:
		line := "hooks = true " + codexRequirementsPinLineMarker + newline
		rendered = spliceCodexRequirementsPin(raw, layout.featuresHeaderLineEnd, line, newline)
	case layout.featuresDottedRoot:
		// Root keys may only precede the first table header, so the dotted
		// form goes at the top of the document.
		line := "features.hooks = true " + codexRequirementsPinLineMarker + newline
		rendered = append([]byte(line), raw...)
	default:
		rendered = appendCodexRequirementsPinRegion(raw, newline)
	}
	expected, err := parseCodexRequirementsPinModel(raw)
	if err != nil {
		return nil, false, err
	}
	features, _ := expected["features"].(map[string]interface{})
	if features == nil {
		features = map[string]interface{}{}
	}
	features["hooks"] = true
	expected["features"] = features
	if err := requireCodexRequirementsPinModel(rendered, expected, errCodexRequirementsPinUneditable); err != nil {
		return nil, false, err
	}
	return rendered, true, nil
}

// removeCodexRequirementsPin removes exactly the bytes DefenseClaw added.
// removeFile is true when nothing but whitespace remains, which is the case
// when DefenseClaw created the file. changed is false when the document holds
// no DefenseClaw pin. DefenseClaw bytes that cannot be removed exactly, such
// as a region whose BEGIN or END marker was deleted, fail closed with
// guidance.
func removeCodexRequirementsPin(raw []byte) (rendered []byte, removeFile, changed bool, err error) {
	model, err := parseCodexRequirementsPinModel(raw)
	if err != nil {
		return nil, false, false, err
	}
	lines := codexRequirementsPinLines(raw)
	keep := make([]bool, len(lines))
	for index := range keep {
		keep[index] = true
	}
	removedRegion := false
	removedLine := false
	begin := -1
	for index, line := range lines {
		switch codexRequirementsPinTrim(raw[line[0]:line[1]]) {
		case codexRequirementsPinRegionBegin:
			begin = index
		case codexRequirementsPinRegionEnd:
			if begin < 0 {
				// An END marker without an open BEGIN: the region's start is
				// unknown, so DefenseClaw's hooks = true above it would
				// otherwise stay in force as if the administrator had set it.
				return nil, false, false, errCodexRequirementsPinUnremovable
			}
			for drop := begin; drop <= index; drop++ {
				keep[drop] = false
			}
			// appendCodexRequirementsPinRegion separates the region from
			// earlier content with one blank line.
			if begin > 0 && keep[begin-1] && codexRequirementsPinTrim(raw[lines[begin-1][0]:lines[begin-1][1]]) == "" {
				keep[begin-1] = false
			}
			removedRegion = true
			begin = -1
		case "hooks = true " + codexRequirementsPinLineMarker,
			"features.hooks = true " + codexRequirementsPinLineMarker:
			if begin < 0 {
				keep[index] = false
				removedLine = true
			}
		}
	}
	if begin >= 0 {
		// A BEGIN marker without its END: the region's extent is unknown.
		return nil, false, false, errCodexRequirementsPinUnremovable
	}
	if !removedRegion && !removedLine {
		return raw, false, false, nil
	}
	var out bytes.Buffer
	for index, line := range lines {
		if keep[index] {
			out.Write(raw[line[0]:line[1]])
		}
	}
	rendered = out.Bytes()
	if codexRequirementsPinHasOwnedBytes(rendered) {
		return nil, false, false, errCodexRequirementsPinUnremovable
	}
	expected := model
	if features, ok := expected["features"].(map[string]interface{}); ok {
		delete(features, "hooks")
		// Without the pin an empty features table may vanish entirely: the
		// region carried its own [features] header, and a dotted
		// features.hooks line is the last features key once the administrator
		// has removed theirs. Absent and empty mean the same to Codex.
		if len(features) == 0 && !codexRequirementsPinDefinesFeatures(rendered) {
			delete(expected, "features")
		}
	}
	if err := requireCodexRequirementsPinModel(rendered, expected, errCodexRequirementsPinUnremovable); err != nil {
		return nil, false, false, err
	}
	return rendered, len(bytes.TrimSpace(rendered)) == 0, true, nil
}

// codexRequirementsPinDefinesFeatures reports whether raw parses with a
// features key.
func codexRequirementsPinDefinesFeatures(raw []byte) bool {
	model, err := parseCodexRequirementsPinModel(raw)
	if err != nil {
		return false
	}
	_, defined := model["features"]
	return defined
}

type codexRequirementsPinLayout struct {
	featuresHeaderLineEnd int
	featuresInline        bool
	featuresDottedRoot    bool
}

// scanCodexRequirementsPinLayout locates how the features table is defined.
// The TOML parser supplies offsets, so bracketed text inside strings or
// comments is never mistaken for a header.
func scanCodexRequirementsPinLayout(raw []byte) (codexRequirementsPinLayout, error) {
	layout := codexRequirementsPinLayout{featuresHeaderLineEnd: -1}
	var parser unstable.Parser
	parser.Reset(raw)
	inRoot := true
	for parser.NextExpression() {
		node := parser.Expression()
		if node.Kind != unstable.Table && node.Kind != unstable.ArrayTable && node.Kind != unstable.KeyValue {
			continue
		}
		var keys []string
		keyOffset := -1
		iterator := node.Key()
		for iterator.Next() {
			key := iterator.Node()
			if keyOffset < 0 {
				keyOffset = int(key.Raw.Offset)
			}
			keys = append(keys, string(key.Data))
		}
		if keyOffset < 0 || keyOffset > len(raw) || len(keys) == 0 {
			return layout, errCodexRequirementsPinUneditable
		}
		switch node.Kind {
		case unstable.Table:
			inRoot = false
			if len(keys) == 1 && keys[0] == "features" {
				layout.featuresHeaderLineEnd = codexRequirementsPinLineEnd(raw, keyOffset)
			}
		case unstable.ArrayTable:
			inRoot = false
			if keys[0] == "features" {
				return layout, errCodexRequirementsPinUneditable
			}
		case unstable.KeyValue:
			if !inRoot || keys[0] != "features" {
				continue
			}
			if len(keys) == 1 {
				layout.featuresInline = true
			} else {
				layout.featuresDottedRoot = true
			}
		}
	}
	if err := parser.Error(); err != nil {
		return layout, fmt.Errorf("parse Codex requirements: %w", err)
	}
	return layout, nil
}

func codexRequirementsPinHasOwnedBytes(raw []byte) bool {
	for _, line := range codexRequirementsPinLines(raw) {
		switch codexRequirementsPinTrim(raw[line[0]:line[1]]) {
		case codexRequirementsPinRegionBegin,
			codexRequirementsPinRegionEnd,
			"hooks = true " + codexRequirementsPinLineMarker,
			"features.hooks = true " + codexRequirementsPinLineMarker:
			return true
		}
	}
	return false
}

// requireCodexRequirementsPinModel returns failure unless rendered parses to
// exactly the expected model.
func requireCodexRequirementsPinModel(rendered []byte, expected map[string]interface{}, failure error) error {
	got, err := parseCodexRequirementsPinModel(rendered)
	if err != nil {
		return fmt.Errorf("%w: %v", failure, err)
	}
	if !reflect.DeepEqual(got, expected) {
		return failure
	}
	return nil
}

func codexRequirementsPinNewline(raw []byte) string {
	if bytes.Contains(raw, []byte("\r\n")) {
		return "\r\n"
	}
	return "\n"
}

// spliceCodexRequirementsPin inserts line at offset, the start of the line
// after the [features] header. A header on the unterminated last line first
// gets its line ending.
func spliceCodexRequirementsPin(raw []byte, offset int, line, newline string) []byte {
	var out bytes.Buffer
	out.Grow(len(raw) + len(line) + len(newline))
	out.Write(raw[:offset])
	if offset == len(raw) && offset > 0 && raw[offset-1] != '\n' {
		out.WriteString(newline)
	}
	out.WriteString(line)
	out.Write(raw[offset:])
	return out.Bytes()
}

func appendCodexRequirementsPinRegion(raw []byte, newline string) []byte {
	var out bytes.Buffer
	out.Grow(len(raw) + 160)
	out.Write(raw)
	if len(bytes.TrimSpace(raw)) > 0 {
		if raw[len(raw)-1] != '\n' {
			out.WriteString(newline)
		}
		out.WriteString(newline)
	}
	out.WriteString(codexRequirementsPinRegionBegin + newline)
	out.WriteString("[features]" + newline)
	out.WriteString("hooks = true" + newline)
	out.WriteString(codexRequirementsPinRegionEnd + newline)
	return out.Bytes()
}

// codexRequirementsPinLineEnd returns the offset just past the newline that
// ends the line containing offset, or len(raw) for an unterminated line.
func codexRequirementsPinLineEnd(raw []byte, offset int) int {
	if index := bytes.IndexByte(raw[offset:], '\n'); index >= 0 {
		return offset + index + 1
	}
	return len(raw)
}

// codexRequirementsPinLines splits raw into [start, end) ranges that keep
// their line terminators.
func codexRequirementsPinLines(raw []byte) [][2]int {
	var lines [][2]int
	for start := 0; start < len(raw); {
		end := len(raw)
		if index := bytes.IndexByte(raw[start:], '\n'); index >= 0 {
			end = start + index + 1
		}
		lines = append(lines, [2]int{start, end})
		start = end
	}
	return lines
}

func codexRequirementsPinTrim(line []byte) string {
	return string(bytes.Trim(line, " \t\r\n"))
}
