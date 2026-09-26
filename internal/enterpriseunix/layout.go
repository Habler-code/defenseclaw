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
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Payload binaries. The ACP mediator is optional.
const (
	binGateway      = "defenseclaw-gateway"
	binHook         = "defenseclaw-hook"
	binSensorHelper = "defenseclaw-sensor-helper"
	binACP          = "defenseclaw-acp"
)

var requiredBinaries = []string{binGateway, binHook, binSensorHelper}
var optionalBinaries = []string{binACP}

// desiredDir is a directory the lifecycle owns or must be able to rely on.
type desiredDir struct {
	Path  string
	Mode  os.FileMode
	Owner fileOwner
	// External directories (vendor policy parents, shared parents such as
	// /opt/cisco) are created when absent and recorded for uninstall, but an
	// existing one is never re-moded or re-owned.
	External bool
}

// desiredFile is a file the lifecycle installs.
type desiredFile struct {
	Path  string
	Data  []byte
	Src   string // rooted source for streamed binaries; Data is nil then
	SHA   string
	Mode  os.FileMode
	Owner fileOwner
	Kind  string
}

// managedDirs returns the DefenseClaw tree for the service account.
func (e *Env) managedDirs(account Account, loadCredential bool) []desiredDir {
	root := rootOwner()
	service := fileOwner{UID: account.UID, GID: account.GID}
	rootService := fileOwner{UID: 0, GID: account.GID}
	l := e.Layout
	secretsMode, secretsOwner := os.FileMode(0o750), rootService
	if loadCredential {
		secretsMode, secretsOwner = 0o700, root
	}
	if e.GOOS == "darwin" {
		return []desiredDir{
			{Path: "/opt", Mode: 0o755, Owner: root, External: true},
			{Path: "/opt/cisco", Mode: 0o755, Owner: root, External: true},
			{Path: l.InstallRoot, Mode: 0o755, Owner: root},
			{Path: l.BinDir, Mode: 0o755, Owner: root},
			{Path: l.ConfigDir, Mode: 0o755, Owner: root},
			{Path: l.PolicyDir, Mode: 0o750, Owner: rootService},
			{Path: l.SecretsDir, Mode: secretsMode, Owner: secretsOwner},
			{Path: filepath.Dir(l.ManifestPath), Mode: 0o750, Owner: rootService},
			{Path: l.DataDir, Mode: 0o750, Owner: service},
			{Path: l.GuardianAuthDir, Mode: 0o750, Owner: rootService},
			{Path: l.LifecycleDir, Mode: 0o700, Owner: root},
			{Path: "/Library/Logs/Cisco", Mode: 0o755, Owner: root, External: true},
			{Path: l.LogDir, Mode: 0o755, Owner: root},
			{Path: filepath.Join(l.LogDir, "gateway"), Mode: 0o750, Owner: service},
			{Path: l.HookSocketDir, Mode: 0o755, Owner: service},
		}
	}
	return []desiredDir{
		{Path: l.InstallRoot, Mode: 0o755, Owner: root},
		{Path: l.BinDir, Mode: 0o755, Owner: root},
		{Path: l.ConfigDir, Mode: 0o755, Owner: root},
		{Path: l.PolicyDir, Mode: 0o750, Owner: rootService},
		{Path: l.SecretsDir, Mode: secretsMode, Owner: secretsOwner},
		{Path: filepath.Dir(l.ManifestPath), Mode: 0o750, Owner: rootService},
		{Path: l.DataDir, Mode: 0o750, Owner: service},
		{Path: l.GuardianAuthDir, Mode: 0o750, Owner: rootService},
		{Path: l.LifecycleDir, Mode: 0o700, Owner: root},
		{Path: l.LogDir, Mode: 0o750, Owner: service},
		// tmpfiles recreates it at boot; the gateway binds hook.sock here
		// when it runs without socket activation.
		{Path: l.HookSocketDir, Mode: 0o755, Owner: service},
	}
}

// machinePolicyDirs are the vendor machine-policy parents the guardian may
// write, per connector and OS. Only connectors whose vendor documents a
// machine policy location appear here; the machine-policy stream owns the
// contents of these directories.
func machinePolicyDirs(goos, connector string) []string {
	if goos == "darwin" {
		switch connector {
		case "codex":
			return []string{"/etc/codex"}
		case "claudecode":
			return []string{"/Library/Application Support/ClaudeCode", "/Library/Application Support/ClaudeCode/managed-settings.d"}
		case "cursor":
			return []string{"/Library/Application Support/Cursor"}
		case "copilot":
			return []string{"/etc/github-copilot", "/etc/github-copilot/policy.d"}
		}
		return nil
	}
	switch connector {
	case "codex":
		return []string{"/etc/codex"}
	case "claudecode":
		return []string{"/etc/claude-code", "/etc/claude-code/managed-settings.d"}
	case "cursor":
		return []string{"/etc/cursor"}
	case "copilot":
		return []string{"/etc/github-copilot", "/etc/github-copilot/policy.d"}
	}
	return nil
}

// MachinePolicyConnectors are the connectors whose DefenseClaw hooks can be
// published through vendor machine policy on goos.
func MachinePolicyConnectors(goos string, enabled []string) []string {
	out := []string{}
	for _, connector := range enabled {
		if len(machinePolicyDirs(goos, connector)) > 0 {
			out = append(out, connector)
		}
	}
	sort.Strings(out)
	return out
}

// legacyLinuxUnits are unit files earlier manual Linux deployments and
// test harnesses left behind. Adoption stops, disables and removes them.
var legacyLinuxUnits = []string{
	"defenseclaw-hook-guardian.timer",
	"defenseclaw-hook-guardian@.service",
	"defenseclaw-hook-guardian-watch.service",
	"defenseclaw-enterprise-test.service",
}

// tmpfilesInstallPath and sysusersInstallPath depend on the channel: the
// package owns /usr/lib, the payload channel writes /etc.
func tmpfilesInstallPath(channel string) string {
	if channel == ChannelPackage {
		return "/usr/lib/tmpfiles.d/defenseclaw.conf"
	}
	return "/etc/tmpfiles.d/defenseclaw.conf"
}

func sysusersInstallPath(channel string) string {
	if channel == ChannelPackage {
		return "/usr/lib/sysusers.d/defenseclaw.conf"
	}
	return "/etc/sysusers.d/defenseclaw.conf"
}

// secureClientPresent reports a Secure Client DefenseClaw layout, whose
// services share the port and are mutually exclusive with standalone.
func (e *Env) secureClientPresent() (bool, string) {
	candidates := []string{"/opt/cisco/secureclient/defenseclaw"}
	if e.GOOS == "darwin" {
		matches, _ := filepath.Glob(e.P("/Library/LaunchDaemons/com.cisco.secureclient.defenseclaw*.plist"))
		for _, match := range matches {
			return true, match
		}
	}
	for _, candidate := range candidates {
		if exists(e.P(candidate)) {
			return true, candidate
		}
	}
	return false, ""
}

// unmanagedLeftovers lists pre-existing DefenseClaw machine state that no
// committed deployment record accounts for. Inputs an MDM may stage before
// installing (config, policies, secrets, manifest) are not leftovers, and
// neither are binaries a package placed for the package channel.
func (e *Env) unmanagedLeftovers(services ServiceManager, channel string) []string {
	l := e.Layout
	candidates := []string{l.DescriptorPath}
	if channel != ChannelPackage {
		candidates = append(candidates, filepath.Join(l.BinDir, binGateway))
	}
	for _, dir := range []string{l.DataDir, l.GuardianAuthDir} {
		if entries, err := os.ReadDir(e.P(dir)); err == nil && len(entries) > 0 {
			candidates = append(candidates, dir)
		}
	}
	for _, unit := range services.Units() {
		if channel != ChannelPackage || e.GOOS == "darwin" {
			candidates = append(candidates, services.DefinitionPath(unit, ChannelPayload))
		}
	}
	if e.GOOS == "linux" {
		for _, name := range legacyLinuxUnits {
			candidates = append(candidates, filepath.Join("/etc/systemd/system", name))
		}
	}
	found := []string{}
	seen := map[string]bool{}
	for _, candidate := range candidates {
		if seen[candidate] {
			continue
		}
		seen[candidate] = true
		if exists(e.P(candidate)) {
			found = append(found, candidate)
		}
	}
	sort.Strings(found)
	return found
}

// ownedParent reports whether dir is a directory the lifecycle may remove
// once empty: a systemd drop-in directory of a DefenseClaw unit.
func ownedParent(dir string) bool {
	return strings.HasPrefix(dir, "/etc/systemd/system/defenseclaw-") && strings.HasSuffix(dir, ".d")
}
