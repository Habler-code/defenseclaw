// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/pelletier/go-toml/v2"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// The foreign-hook guard exists because several agents run every
// registered hook or plugin and let any of them rewrite a tool call's input
// (Claude/Codex/Devin updatedInput, Cursor updated_input, Copilot
// modifiedArgs, OpenCode tool.execute.before) or approve it after
// DefenseClaw inspected the original. Where the vendor has no
// managed-hooks-only lock, a standard user (or a prompt-injected agent)
// could otherwise add such a hook and run something DefenseClaw never saw.
//
// Two enforcement points share this scanner:
//   - the admin-owned hook binary evaluates user and project hook files on
//     every call and fails closed while an unapproved foreign hook exists;
//   - the guardian removes foreign entries from user-level vendor config
//     (backing them up and auditing each removal). Project files are never
//     rewritten; they are reported and blocked.

// Scopes.
const (
	ScopeUser    = "user"
	ScopeProject = "project"
)

// Source formats.
const (
	formatGrouped     = "grouped"      // Claude-style {"hooks":{event:[{matcher,hooks:[handler]}]}}
	formatHooksObject = "hooks-object" // Devin hooks.v1.json: the whole file is the hooks object
	formatFlat        = "flat"         // Cursor/Copilot {"hooks":{event:[handler]}}
	formatFlatDir     = "flat-dir"     // directory of flat JSON files
	formatCodexTOML   = "codex-toml"   // Codex config.toml [[hooks.<event>]]
	formatPluginDir   = "plugin-dir"   // directory of plugin source files
	formatPluginList  = "plugin-list"  // JSON "plugin" array (OpenCode)
)

// guardFileLimit bounds every user or project hook file the guard reads.
const guardFileLimit = 1 << 20

// maxProjectDepth bounds the ancestor walk from the working directory.
const maxProjectDepth = 12

// hookSource is one user or project file (or directory) to scan.
type hookSource struct {
	scope  string
	path   string
	format string
}

// Finding is one foreign hook entry or plugin.
type Finding struct {
	Connector string `json:"connector"`
	Scope     string `json:"scope"`
	Path      string `json:"path"`
	Event     string `json:"event,omitempty"`
	Command   string `json:"command,omitempty"`
	Digest    string `json:"digest"`
	Reason    string `json:"reason,omitempty"`
	Allowed   bool   `json:"allowed"`
}

// GuardRequest describes one scan.
type GuardRequest struct {
	Connector  string
	GOOS       string
	Home       string
	WorkingDir string
	HookBinary string
	Policy     PublicConnectorPolicy
	// Getenv returns the agent's environment (vendor config-dir overrides).
	Getenv func(string) string
	// OwnedCommands are the exact commands of DefenseClaw's own per-user
	// registration (connector.PerUserOwnedHookCommands); they are not
	// foreign.
	OwnedCommands []string
}

// GuardDecision is the scan result.
type GuardDecision struct {
	Findings []Finding `json:"findings"`
	Deny     bool      `json:"deny"`
	Reason   string    `json:"reason,omitempty"`
}

func (r GuardRequest) getenv(key string) string {
	if r.Getenv == nil {
		return ""
	}
	return strings.TrimSpace(r.Getenv(key))
}

func (r GuardRequest) goos() string {
	if r.GOOS != "" {
		return r.GOOS
	}
	return runtimeGOOS()
}

// projectDirs returns the working directory and its ancestors up to the
// git root (inclusive), stopping before the user's home and the root.
func projectDirs(workingDir, home string) []string {
	if strings.TrimSpace(workingDir) == "" {
		return nil
	}
	dir := filepath.Clean(workingDir)
	home = filepath.Clean(home)
	var dirs []string
	for depth := 0; depth < maxProjectDepth; depth++ {
		if dir == home || dir == filepath.Dir(dir) {
			break
		}
		dirs = append(dirs, dir)
		if info, err := os.Lstat(filepath.Join(dir, ".git")); err == nil && (info.IsDir() || info.Mode().IsRegular()) {
			break
		}
		dir = filepath.Dir(dir)
	}
	return dirs
}

// guardSources lists every user and project location for connector.
func guardSources(req GuardRequest) []hookSource {
	home := req.Home
	var sources []hookSource
	user := func(format string, parts ...string) {
		sources = append(sources, hookSource{scope: ScopeUser, path: filepath.Join(parts...), format: format})
	}
	projects := projectDirs(req.WorkingDir, home)
	project := func(format string, rel ...string) {
		for _, dir := range projects {
			sources = append(sources, hookSource{scope: ScopeProject, path: filepath.Join(append([]string{dir}, rel...)...), format: format})
		}
	}
	xdgConfig := req.getenv("XDG_CONFIG_HOME")
	if xdgConfig == "" {
		xdgConfig = filepath.Join(home, ".config")
	}
	// Cursor, Copilot and Devin also load Claude-format hook files by
	// default (third-party extensibility), so those run inside the agent too.
	claudeFormat := func(includeUser bool) {
		if includeUser {
			user(formatGrouped, home, ".claude", "settings.json")
		}
		project(formatGrouped, ".claude", "settings.json")
		project(formatGrouped, ".claude", "settings.local.json")
	}
	switch req.Connector {
	case ConnectorCursor:
		user(formatFlat, home, ".cursor", "hooks.json")
		project(formatFlat, ".cursor", "hooks.json")
		claudeFormat(true)
	case ConnectorCopilot:
		copilotHome := req.getenv("COPILOT_HOME")
		if copilotHome == "" {
			copilotHome = filepath.Join(home, ".copilot")
		}
		user(formatFlatDir, copilotHome, "hooks")
		user(formatFlat, copilotHome, "settings.json")
		project(formatFlatDir, ".github", "hooks")
		project(formatFlat, ".github", "copilot", "settings.json")
		project(formatFlat, ".github", "copilot", "settings.local.json")
		claudeFormat(false)
	case "devin":
		if req.goos() == "windows" {
			if appData := req.getenv("APPDATA"); appData != "" {
				user(formatGrouped, appData, "devin", "config.json")
			}
		} else {
			user(formatGrouped, xdgConfig, "devin", "config.json")
		}
		user(formatGrouped, home, ".claude", "settings.local.json")
		project(formatHooksObject, ".devin", "hooks.v1.json")
		project(formatGrouped, ".devin", "config.json")
		project(formatGrouped, ".devin", "config.local.json")
		claudeFormat(true)
	case ConnectorClaudeCode:
		claudeDir := req.getenv("CLAUDE_CONFIG_DIR")
		if claudeDir == "" {
			claudeDir = filepath.Join(home, ".claude")
		}
		user(formatGrouped, claudeDir, "settings.json")
		project(formatGrouped, ".claude", "settings.json")
		project(formatGrouped, ".claude", "settings.local.json")
	case ConnectorCodex:
		codexHome := req.getenv("CODEX_HOME")
		if codexHome == "" {
			codexHome = filepath.Join(home, ".codex")
		}
		user(formatCodexTOML, codexHome, "config.toml")
		user(formatGrouped, codexHome, "hooks.json")
		project(formatCodexTOML, ".codex", "config.toml")
		project(formatGrouped, ".codex", "hooks.json")
	case "opencode":
		user(formatPluginDir, xdgConfig, "opencode", "plugins")
		user(formatPluginDir, xdgConfig, "opencode", "plugin")
		user(formatPluginList, xdgConfig, "opencode", "opencode.json")
		if custom := req.getenv("OPENCODE_CONFIG"); custom != "" && filepath.IsAbs(custom) {
			user(formatPluginList, custom)
		}
		project(formatPluginDir, ".opencode", "plugins")
		project(formatPluginDir, ".opencode", "plugin")
		project(formatPluginList, "opencode.json")
	case "amp":
		user(formatPluginDir, xdgConfig, "amp", "plugins")
		project(formatPluginDir, ".amp", "plugins")
	}
	return sources
}

// ownedCommands are the exact admin-binary registrations DefenseClaw
// renders; anything else is foreign. Per-user scripts left by an unmanaged
// install are foreign too: they are user-owned code.
func (r GuardRequest) ownedCommand(command string) bool {
	command = strings.TrimSpace(command)
	for _, owned := range r.OwnedCommands {
		if owned != "" && command == owned {
			return true
		}
	}
	return ownedCommand(command, r.HookBinary)
}

func ownedCommand(command, hookBinary string) bool {
	if command == "" || hookBinary == "" {
		return false
	}
	// Windows exec-form handlers carry the binary alone in command.
	if strings.EqualFold(command, hookBinary) {
		return true
	}
	rest, ok := strings.CutPrefix(command, shellQuote(hookBinary)+" hook --connector ")
	if !ok {
		return false
	}
	// Any DefenseClaw connector registration of the admin binary is owned:
	// the binary is administrator-owned and only talks to the gateway.
	name, rest, _ := strings.Cut(rest, " ")
	if !validConnectorToken(name) {
		return false
	}
	if rest == "--enterprise-managed" {
		return true
	}
	event, ok := strings.CutPrefix(rest, "--enterprise-managed --event ")
	if !ok {
		return false
	}
	event = strings.TrimSuffix(strings.TrimPrefix(event, "'"), "'")
	return validConnectorToken(event)
}

func validConnectorToken(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, r := range value {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

func handlerCommand(handler any) string {
	for _, key := range []string{"command", "bash", "powershell", "url", "prompt"} {
		if value := stringField(handler, key); value != "" {
			return value
		}
	}
	return ""
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "…"
}

// readGuardFile reads a user or project file without following links.
func readGuardFile(path string) ([]byte, bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, true, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, true, fmt.Errorf("%s is a symbolic link", path)
	}
	if !info.Mode().IsRegular() {
		return nil, false, nil
	}
	file, err := openNoFollow(path)
	if err != nil {
		return nil, true, err
	}
	defer file.Close()
	data, err := readBounded(file, guardFileLimit)
	return data, true, err
}

func findingFor(req GuardRequest, source hookSource, event, command string, digest string, reason string) Finding {
	finding := Finding{
		Connector: req.Connector,
		Scope:     source.scope,
		Path:      source.path,
		Event:     event,
		Command:   truncate(command, 160),
		Digest:    digest,
		Reason:    reason,
	}
	for _, allowed := range req.Policy.AllowedHooks {
		if allowed == digest {
			finding.Allowed = true
		}
	}
	return finding
}

func unreadableFinding(req GuardRequest, source hookSource, err error) Finding {
	return findingFor(req, source, "", "", sha256Hex([]byte(source.path)), "cannot verify hook file: "+err.Error())
}

// scanJSONHooks returns findings for a grouped or flat hooks document.
func scanJSONHooks(req GuardRequest, source hookSource, data []byte) []Finding {
	doc, err := decodeOrderedObject(data)
	if err != nil {
		return []Finding{unreadableFinding(req, source, err)}
	}
	hooks := doc
	if source.format != formatHooksObject {
		hooksValue, _ := doc.get("hooks")
		hooks, _ = hooksValue.(*object)
	} else if nested, ok := doc.get("hooks"); ok {
		if nestedObject, ok := nested.(*object); ok {
			hooks = nestedObject
		}
	}
	if hooks == nil {
		return nil
	}
	var findings []Finding
	for _, event := range hooks.keys {
		value, _ := hooks.get(event)
		list, _ := value.([]any)
		for _, item := range list {
			handlers := []any{item}
			if source.format == formatGrouped || source.format == formatHooksObject {
				handlers = handlersOf(item)
			}
			for _, handler := range handlers {
				command := handlerCommand(handler)
				if req.ownedCommand(command) {
					continue
				}
				findings = append(findings, findingFor(req, source, event, command, sha256Hex(canonicalJSON(handler)), ""))
			}
		}
	}
	return findings
}

func scanCodexTOML(req GuardRequest, source hookSource, data []byte) []Finding {
	cfg := map[string]any{}
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return []Finding{unreadableFinding(req, source, err)}
	}
	hooks, _ := cfg["hooks"].(map[string]any)
	events := make([]string, 0, len(hooks))
	for event := range hooks {
		events = append(events, event)
	}
	sort.Strings(events)
	var findings []Finding
	for _, event := range events {
		list, ok := hooks[event].([]any)
		if !ok {
			continue
		}
		for _, group := range list {
			for _, handler := range handlersOf(group) {
				command := handlerCommand(handler)
				if req.ownedCommand(command) {
					continue
				}
				findings = append(findings, findingFor(req, source, event, command, sha256Hex(canonicalJSON(handler)), ""))
			}
		}
	}
	return findings
}

var ownedPluginNames = map[string]bool{"defenseclaw.ts": true, "defenseclaw.js": true, "defenseclaw.mjs": true}

func scanPluginDir(req GuardRequest, source hookSource) []Finding {
	info, err := os.Lstat(source.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return []Finding{unreadableFinding(req, source, err)}
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return []Finding{unreadableFinding(req, source, fmt.Errorf("%s is a symbolic link", source.path))}
	}
	if !info.IsDir() {
		return nil
	}
	entries, err := os.ReadDir(source.path)
	if err != nil {
		return []Finding{unreadableFinding(req, source, err)}
	}
	var findings []Finding
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, ".") || ownedPluginNames[name] {
			continue
		}
		path := filepath.Join(source.path, name)
		child := hookSource{scope: source.scope, path: path, format: formatPluginDir}
		if entry.IsDir() {
			findings = append(findings, findingFor(req, child, "", name, sha256Hex([]byte("dir:"+name)), "plugin directory"))
			continue
		}
		data, _, err := readGuardFile(path)
		if err != nil {
			findings = append(findings, unreadableFinding(req, child, err))
			continue
		}
		findings = append(findings, findingFor(req, child, "", name, sha256Hex(data), "plugin"))
	}
	return findings
}

func scanPluginList(req GuardRequest, source hookSource, data []byte) []Finding {
	doc, err := decodeOrderedObject(data)
	if err != nil {
		return []Finding{unreadableFinding(req, source, err)}
	}
	value, _ := doc.get("plugin")
	list, _ := value.([]any)
	var findings []Finding
	for _, item := range list {
		name := ""
		switch v := item.(type) {
		case string:
			name = v
		case []any:
			if len(v) > 0 {
				name, _ = v[0].(string)
			}
		}
		if ownedPluginNames[filepath.Base(strings.TrimPrefix(name, "file://"))] {
			continue
		}
		findings = append(findings, findingFor(req, source, "", name, sha256Hex(canonicalJSON(item)), "plugin"))
	}
	return findings
}

// ScanForeignHooks returns every foreign hook or plugin for req.
func ScanForeignHooks(req GuardRequest) []Finding {
	var findings []Finding
	for _, source := range guardSources(req) {
		switch source.format {
		case formatFlatDir:
			entries, err := os.ReadDir(source.path)
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					findings = append(findings, unreadableFinding(req, source, err))
				}
				continue
			}
			if info, err := os.Lstat(source.path); err == nil && info.Mode()&os.ModeSymlink != 0 {
				findings = append(findings, unreadableFinding(req, source, fmt.Errorf("%s is a symbolic link", source.path)))
				continue
			}
			for _, entry := range entries {
				if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
					continue
				}
				child := hookSource{scope: source.scope, path: filepath.Join(source.path, entry.Name()), format: formatFlat}
				data, exists, err := readGuardFile(child.path)
				if err != nil {
					findings = append(findings, unreadableFinding(req, child, err))
					continue
				}
				if exists {
					findings = append(findings, scanJSONHooks(req, child, data)...)
				}
			}
		case formatPluginDir:
			findings = append(findings, scanPluginDir(req, source)...)
		default:
			data, exists, err := readGuardFile(source.path)
			if err != nil {
				findings = append(findings, unreadableFinding(req, source, err))
				continue
			}
			if !exists || len(bytes.TrimSpace(data)) == 0 {
				continue
			}
			switch source.format {
			case formatCodexTOML:
				findings = append(findings, scanCodexTOML(req, source, data)...)
			case formatPluginList:
				findings = append(findings, scanPluginList(req, source, data)...)
			default:
				findings = append(findings, scanJSONHooks(req, source, data)...)
			}
		}
	}
	return findings
}

// EvaluateForeignHooks scans and decides. With foreign_hooks remove, any
// unapproved finding denies; report allows but returns the findings; allow
// (or a connector the guard does not cover) skips the scan.
func EvaluateForeignHooks(req GuardRequest) GuardDecision {
	if !req.Policy.Guard || req.Policy.ForeignHooks == config.ForeignHooksAllow {
		return GuardDecision{}
	}
	decision := GuardDecision{Findings: ScanForeignHooks(req)}
	var blocking []Finding
	for _, finding := range decision.Findings {
		if !finding.Allowed {
			blocking = append(blocking, finding)
		}
	}
	if len(blocking) == 0 || req.Policy.ForeignHooks != config.ForeignHooksRemove {
		return decision
	}
	first := blocking[0]
	what := "defines a hook"
	if first.Reason == "plugin" || first.Reason == "plugin directory" {
		what = "adds a plugin"
	} else if strings.HasPrefix(first.Reason, "cannot verify") {
		what = "cannot be verified (" + strings.TrimPrefix(first.Reason, "cannot verify hook file: ") + ")"
	}
	decision.Deny = true
	decision.Reason = fmt.Sprintf(
		"enterprise_foreign_hook_blocked: your organization blocks %s hooks it has not approved, because they can change a tool call after DefenseClaw checks it. The %s file %s %s (digest sha256:%s)%s. Remove it, or ask your administrator to add the digest to enterprise.machine_policy.connectors.%s.allowed_hooks.",
		req.Connector, first.Scope, first.Path, what, first.Digest, moreFindings(len(blocking)-1), req.Connector,
	)
	return decision
}

func moreFindings(n int) string {
	if n <= 0 {
		return ""
	}
	return fmt.Sprintf(" and %d more", n)
}
