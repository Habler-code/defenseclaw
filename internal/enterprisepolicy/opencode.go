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
	"errors"
	"fmt"
	"os"
	"path"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// OpenCode merges its managed config (/etc/opencode, %ProgramData%\opencode,
// /Library/Application Support/opencode) above user, project and
// OPENCODE_CONFIG_CONTENT layers. A managed "plugin" entry naming an
// absolute plugin path survived every user override in live tests and ran
// after user and project plugins (it saw the final input). That ordering is
// observed, not documented, so the foreign-plugin guard stays on.
//
// The route needs an administrator-owned managed plugin artifact
// (Options.OpenCodePluginPath); without one OpenCode stays per-user.
const opencodeConnector = ConnectorOpenCode

type opencodeTarget struct{}

func (opencodeTarget) Name() string { return opencodeConnector }

// OpenCodeManagedPluginPath is where a standalone install places the
// administrator-owned managed OpenCode plugin. The lifecycle passes it as
// Options.OpenCodePluginPath only when the artifact is installed.
func OpenCodeManagedPluginPath(layout managed.StandaloneLayout) string {
	if layout.GOOS == "windows" {
		return strings.TrimRight(layout.InstallRoot, `\`) + `\share\opencode\defenseclaw.js`
	}
	return path.Join(layout.InstallRoot, "share", "opencode", "defenseclaw.js")
}

// OpenCodeManagedConfigPath returns the managed config file, preferring an
// existing opencode.jsonc.
func OpenCodeManagedConfigPath(opts Options) (string, error) {
	dir, err := machinePath(opts,
		"/etc/opencode",
		"/Library/Application Support/opencode",
		func(_, programData string) string { return programData + `\opencode` })
	if err != nil {
		return "", err
	}
	jsonc := joinFor(opts, dir, "opencode.jsonc")
	if _, err := os.Lstat(platformPath(opts, jsonc)); err == nil {
		return jsonc, nil
	}
	return joinFor(opts, dir, "opencode.json"), nil
}

func (o Options) openCodeArtifactInstalled() bool {
	if o.OpenCodePluginPath == "" {
		return false
	}
	info, err := os.Lstat(platformPath(o, o.OpenCodePluginPath))
	return err == nil && info.Mode().IsRegular()
}

func (opencodeTarget) Paths(opts Options) ([]string, error) {
	path, err := OpenCodeManagedConfigPath(opts)
	if err != nil {
		return nil, err
	}
	return []string{path}, nil
}

func opencodeEntryIsOwned(opts Options, raw any) bool {
	value, ok := raw.(string)
	if !ok || opts.OpenCodePluginPath == "" {
		return false
	}
	return value == opts.OpenCodePluginPath || value == "file://"+opts.OpenCodePluginPath
}

func mergeOpenCodeConfig(opts Options, current []byte) ([]byte, bool, error) {
	doc, err := decodeOrderedObject(current)
	if err != nil {
		return nil, false, fmt.Errorf("parse OpenCode managed config (comments in .jsonc cannot be merged): %w", err)
	}
	value, _ := doc.get("plugin")
	list, _ := value.([]any)
	if value != nil && list == nil {
		return nil, false, fmt.Errorf("OpenCode managed config plugin has unsupported type %T", value)
	}
	kept := make([]any, 0, len(list)+1)
	owned := 0
	for _, item := range list {
		if opencodeEntryIsOwned(opts, item) {
			owned++
			if owned > 1 {
				continue
			}
		}
		kept = append(kept, item)
	}
	exact := owned == 1
	if owned == 0 {
		kept = append(kept, opts.OpenCodePluginPath)
	}
	doc.set("plugin", kept)
	rendered, err := encodeOrdered(doc)
	return rendered, exact && len(kept) == len(list), err
}

func stripOpenCodeConfig(opts Options, current []byte) ([]byte, bool, error) {
	doc, err := decodeOrderedObject(current)
	if err != nil {
		return nil, false, err
	}
	value, _ := doc.get("plugin")
	list, _ := value.([]any)
	kept := make([]any, 0, len(list))
	for _, item := range list {
		if !opencodeEntryIsOwned(opts, item) {
			kept = append(kept, item)
		}
	}
	if len(kept) == len(list) {
		// Nothing of ours: leave the administrator's bytes alone.
		return current, false, nil
	}
	if len(kept) == 0 {
		doc.delete("plugin")
	} else {
		doc.set("plugin", kept)
	}
	if doc.len() == 0 {
		return nil, true, nil
	}
	rendered, err := encodeOrdered(doc)
	return rendered, false, err
}

func inspectOpenCode(opts Options, current []byte, state *State) error {
	doc, err := decodeOrderedObject(current)
	if err != nil {
		return err
	}
	value, _ := doc.get("plugin")
	list, _ := value.([]any)
	for _, item := range list {
		if opencodeEntryIsOwned(opts, item) {
			state.OwnedEntries++
		} else {
			state.ForeignEntries++
		}
	}
	if state.OwnedEntries != 1 {
		state.conflict("OpenCode managed config has %d DefenseClaw plugin entries, want exactly one", state.OwnedEntries)
	}
	if !opts.openCodeArtifactInstalled() {
		state.conflict("managed OpenCode plugin %s is missing", opts.OpenCodePluginPath)
	}
	state.detail("OpenCode ran the managed plugin after user and project plugins in live tests, but plugin order is not a documented contract; the foreign-plugin guard stays on")
	return nil
}

func newOpenCodeState(opts Options, policy config.ResolvedConnectorPolicy, path string) State {
	return State{Connector: opencodeConnector, Route: RouteMachinePolicy, Ownership: policy.Ownership, ForeignHooks: policy.ForeignHooks, Paths: []string{path}}
}

func (t opencodeTarget) Reconcile(opts Options) (State, error) {
	if err := opts.Validate(); err != nil {
		return State{}, err
	}
	policy := opts.PolicyFor(opencodeConnector)
	path, err := OpenCodeManagedConfigPath(opts)
	if err != nil {
		return State{}, err
	}
	state := newOpenCodeState(opts, policy, path)
	if !opts.openCodeArtifactInstalled() || policy.Ownership == config.MachinePolicyOwnershipOff {
		state.Route = RoutePerUser
		state.detail("no managed OpenCode plugin artifact is installed; OpenCode uses the per-user plugin, guardian repair and the foreign-plugin guard")
		return state, nil
	}
	current, exists, err := readPolicyFile(opts, path)
	if err != nil {
		return state, err
	}
	if policy.Ownership == config.MachinePolicyOwnershipMerge {
		rendered, exact, err := mergeOpenCodeConfig(opts, current)
		if err != nil {
			state.conflict("%v; use ownership: verify_only", err)
			state.finish()
			return state, nil
		}
		changed, err := publishWithRecord(opts, opencodeConnector, path, current, exists, rendered, exact, &state)
		if err != nil {
			return state, err
		}
		state.Changed = changed
		current = rendered
	}
	if err := inspectOpenCode(opts, current, &state); err != nil {
		return state, err
	}
	state.finish()
	return state, nil
}

func (t opencodeTarget) Verify(opts Options) (State, error) {
	if err := opts.Validate(); err != nil {
		return State{}, err
	}
	policy := opts.PolicyFor(opencodeConnector)
	path, err := OpenCodeManagedConfigPath(opts)
	if err != nil {
		return State{}, err
	}
	state := newOpenCodeState(opts, policy, path)
	if !opts.openCodeArtifactInstalled() || policy.Ownership == config.MachinePolicyOwnershipOff {
		state.Route = RoutePerUser
		return state, nil
	}
	current, exists, err := readPolicyFile(opts, path)
	if err != nil {
		return state, err
	}
	if !exists {
		state.conflict("%s does not exist", path)
	} else if err := inspectOpenCode(opts, current, &state); err != nil {
		return state, err
	}
	state.finish()
	return state, nil
}

func (t opencodeTarget) RemoveOwned(opts Options) (State, error) {
	path, err := OpenCodeManagedConfigPath(opts)
	if err != nil {
		return State{}, err
	}
	// Removal recognizes DefenseClaw's entry by the artifact path, which
	// StandaloneOptions always sets, even after the artifact is deleted.
	// Without it only a byte-identical postimage is restored.
	state := State{Connector: opencodeConnector, Route: RouteMachinePolicy, Paths: []string{path}}
	err = restoreOrStrip(opts, opencodeConnector, path, func(current []byte) ([]byte, bool, error) {
		return stripOpenCodeConfig(opts, current)
	}, &state)
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return state, err
}

func (opencodeTarget) Export(opts Options, format string) ([]byte, error) {
	if opts.OpenCodePluginPath == "" {
		return nil, errors.New("opencode export needs the managed plugin artifact path")
	}
	if format != "" && format != "json" {
		return nil, fmt.Errorf("opencode policy export supports format json, not %q", format)
	}
	rendered, _, err := mergeOpenCodeConfig(opts, nil)
	return rendered, err
}

func validOpenCodePluginPath(opts Options) error {
	if opts.OpenCodePluginPath == "" {
		return nil
	}
	if opts.goos() == "windows" {
		if !windowsAbsolute(opts.OpenCodePluginPath) {
			return fmt.Errorf("OpenCode plugin path %q is not an absolute Windows path", opts.OpenCodePluginPath)
		}
		return nil
	}
	if !strings.HasPrefix(opts.OpenCodePluginPath, "/") {
		return fmt.Errorf("OpenCode plugin path %q is not absolute", opts.OpenCodePluginPath)
	}
	return nil
}
