//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Unix agent-version discovery for the standalone enumerator.
//
// DiscoverUnixAgentVersion runs inside the per-user apply-target worker
// with the target user's credentials, so reading package metadata under
// the user's home and executing `<cli> --version` happen with that user's
// permissions — never root's. DiscoverUnixMachineAgentVersion runs as root
// but trusts only root-owned, non-writable machine-scoped metadata; it
// lets the enumerator defer a row for a user whose home does not exist
// yet when the agent is installed machine-wide.

const (
	unixAgentVersionMaxBytes = 64 << 10
	unixAgentVersionMaxRunes = 128
	unixAgentVersionTimeout  = 5 * time.Second
	unixAgentVersionOutput   = 512
)

// TrustedBinPrefixesEnv lists extra administrator-controlled install
// prefixes (colon-separated) whose bin/ and lib/node_modules/ the
// discovery searches, e.g. an MDM-managed /opt/agents.
const TrustedBinPrefixesEnv = "DEFENSECLAW_TRUSTED_BIN_PREFIXES"

var unixAgentSemver = regexp.MustCompile(`^[0-9]+\.[0-9]+(\.[0-9]+)?([.+-][0-9A-Za-z.+-]*)?$`)

// unixAgentProbe describes where a connector's CLI leaves metadata.
type unixAgentProbe struct {
	npmPackages []string // package names, checked for a matching "name"
	versionDirs []string // home-relative dirs whose children are version-named
	binaries    []string // CLI names for the `--version` fallback
}

var unixAgentProbes = map[string]unixAgentProbe{
	"codex":       {npmPackages: []string{"@openai/codex"}, binaries: []string{"codex"}},
	"claudecode":  {npmPackages: []string{"@anthropic-ai/claude-code"}, versionDirs: []string{".local/share/claude/versions", "Library/Application Support/Claude/claude-code"}, binaries: []string{"claude"}},
	"cursor":      {versionDirs: []string{".local/share/cursor-agent/versions"}, binaries: []string{"cursor-agent", "agent"}},
	"copilot":     {npmPackages: []string{"@github/copilot"}, binaries: []string{"copilot"}},
	"opencode":    {npmPackages: []string{"opencode-ai"}, binaries: []string{"opencode"}},
	"amp":         {npmPackages: []string{"@ampcode/cli"}, binaries: []string{"amp"}},
	"devin":       {binaries: []string{"devin"}},
	"hermes":      {binaries: []string{"hermes"}},
	"openhands":   {binaries: []string{"openhands"}},
	"omnigent":    {binaries: []string{"omnigent"}},
	"antigravity": {binaries: []string{"agy", "antigravity"}},
	"kiro":        {binaries: []string{"kiro-cli"}},
}

// UnixAgentProbeKnown reports whether discovery knows connector.
func UnixAgentProbeKnown(connector string) bool {
	_, ok := unixAgentProbes[strings.ToLower(strings.TrimSpace(connector))]
	return ok
}

func userNodePrefixes(home string) []string {
	return []string{
		filepath.Join(home, ".npm-global"),
		filepath.Join(home, ".local"),
		filepath.Join(home, ".bun", "install", "global"),
		filepath.Join(home, ".volta", "tools", "image"),
	}
}

// machinePrefixes lists machine-wide install prefixes; tests replace it so
// the developer's own installs do not leak into assertions.
var machinePrefixes = defaultMachinePrefixes

func defaultMachinePrefixes() []string {
	prefixes := []string{"/usr/local", "/usr", "/opt/homebrew"}
	for _, extra := range filepath.SplitList(os.Getenv(TrustedBinPrefixesEnv)) {
		extra = filepath.Clean(strings.TrimSpace(extra))
		if filepath.IsAbs(extra) && extra != "/" {
			prefixes = append(prefixes, extra)
		}
	}
	return prefixes
}

func nodeModulesPackage(prefix, pkg string) []string {
	// npm uses <prefix>/lib/node_modules; bun's global dir is itself
	// node_modules-rooted.
	return []string{
		filepath.Join(prefix, "lib", "node_modules", filepath.FromSlash(pkg), "package.json"),
		filepath.Join(prefix, "node_modules", filepath.FromSlash(pkg), "package.json"),
	}
}

// DiscoverUnixAgentVersion finds connector's installed version for home.
// allowExec enables the `--version` fallback; callers set it only when
// already running with the target user's credentials.
func DiscoverUnixAgentVersion(ctx context.Context, home, connector string, allowExec bool) (string, string) {
	connector = strings.ToLower(strings.TrimSpace(connector))
	probe, ok := unixAgentProbes[connector]
	if !ok {
		return "", fmt.Sprintf("no version probe for connector %s", connector)
	}
	home = filepath.Clean(home)
	for _, pkg := range probe.npmPackages {
		for _, prefix := range append(userNodePrefixes(home), machinePrefixes()...) {
			for _, candidate := range nodeModulesPackage(prefix, pkg) {
				if version, ok := readUnixPackageVersion(candidate, pkg, false); ok {
					return version, ""
				}
			}
		}
	}
	for _, dir := range probe.versionDirs {
		if version := newestVersionDir(filepath.Join(home, filepath.FromSlash(dir))); version != "" {
			return version, ""
		}
	}
	if !allowExec {
		return "", fmt.Sprintf("no %s package metadata under this home", connector)
	}
	for _, binary := range probe.binaries {
		for _, candidate := range unixAgentBinaryCandidates(home, binary) {
			if version := execUnixAgentVersion(ctx, candidate, home); version != "" {
				return version, ""
			}
		}
	}
	return "", fmt.Sprintf("no %s installation found for this user", connector)
}

// DiscoverUnixMachineAgentVersion reads only root-owned, non-writable
// machine-scoped package metadata. Safe to call as root.
func DiscoverUnixMachineAgentVersion(connector string) string {
	probe, ok := unixAgentProbes[strings.ToLower(strings.TrimSpace(connector))]
	if !ok {
		return ""
	}
	for _, pkg := range probe.npmPackages {
		for _, prefix := range machinePrefixes() {
			for _, candidate := range nodeModulesPackage(prefix, pkg) {
				if version, ok := readUnixPackageVersion(candidate, pkg, true); ok {
					return version
				}
			}
		}
	}
	return ""
}

func unixAgentBinaryCandidates(home, binary string) []string {
	dirs := []string{
		filepath.Join(home, ".local", "bin"),
		filepath.Join(home, ".npm-global", "bin"),
		filepath.Join(home, ".bun", "bin"),
		filepath.Join(home, ".opencode", "bin"),
		filepath.Join(home, "bin"),
	}
	for _, prefix := range machinePrefixes() {
		dirs = append(dirs, filepath.Join(prefix, "bin"))
	}
	candidates := make([]string, 0, len(dirs))
	for _, dir := range dirs {
		candidates = append(candidates, filepath.Join(dir, binary))
	}
	return candidates
}

type unixPackageJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// readUnixPackageVersion reads a bounded package.json. When requireRoot is
// set every path element must be root-owned and not group/other writable.
func readUnixPackageVersion(path, wantName string, requireRoot bool) (string, bool) {
	if requireRoot && !rootOwnedChain(path) {
		return "", false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	file, err := os.Open(path)
	if err != nil {
		return "", false
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, unixAgentVersionMaxBytes+1))
	if err != nil || len(data) > unixAgentVersionMaxBytes {
		return "", false
	}
	var parsed unixPackageJSON
	if err := json.Unmarshal(data, &parsed); err != nil {
		return "", false
	}
	if wantName != "" && strings.TrimSpace(parsed.Name) != wantName {
		return "", false
	}
	version := strings.TrimSpace(parsed.Version)
	if !validUnixAgentVersion(version) {
		return "", false
	}
	return version, true
}

func rootOwnedChain(path string) bool {
	for current := filepath.Clean(path); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 {
			return false
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			return false
		}
		if current == filepath.Dir(current) {
			return true
		}
	}
}

// newestVersionDir returns the highest semver-named child of dir.
func newestVersionDir(dir string) string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	var versions []string
	for _, entry := range entries {
		name := entry.Name()
		if validUnixAgentVersion(name) {
			versions = append(versions, name)
		}
		if len(versions) > 256 {
			break
		}
	}
	if len(versions) == 0 {
		return ""
	}
	sort.Slice(versions, func(i, j int) bool { return compareUnixVersions(versions[i], versions[j]) < 0 })
	return versions[len(versions)-1]
}

func compareUnixVersions(a, b string) int {
	parse := func(v string) [3]int {
		var out [3]int
		core := v
		if i := strings.IndexAny(core, "+-"); i >= 0 {
			core = core[:i]
		}
		for i, part := range strings.SplitN(core, ".", 3) {
			n, _ := strconv.Atoi(part)
			out[i] = n
		}
		return out
	}
	pa, pb := parse(a), parse(b)
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1
			}
			return 1
		}
	}
	return strings.Compare(a, b)
}

func validUnixAgentVersion(version string) bool {
	if version == "" || len(version) > unixAgentVersionMaxRunes {
		return false
	}
	return unixAgentSemver.MatchString(version)
}

// ExtractUnixAgentVersion takes the last semver-looking token of a
// `--version` first line ("codex-cli 0.142.0", "2.1.187 (Claude Code)").
func ExtractUnixAgentVersion(line string) string {
	fields := strings.Fields(line)
	for i := range fields {
		token := strings.Trim(fields[i], "()[],v")
		if validUnixAgentVersion(token) {
			return token
		}
	}
	return ""
}

var errUnixAgentVersionOutput = errors.New("agent --version output exceeds bound")

type cappedBuffer struct {
	buf   bytes.Buffer
	limit int
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if c.buf.Len()+len(p) > c.limit {
		remaining := c.limit - c.buf.Len()
		if remaining > 0 {
			c.buf.Write(p[:remaining])
		}
		return 0, errUnixAgentVersionOutput
	}
	return c.buf.Write(p)
}

// execUnixAgentVersion runs candidate --version with a minimal environment
// and a timeout. The caller must already run as the target user.
func execUnixAgentVersion(ctx context.Context, candidate, home string) string {
	info, err := os.Stat(candidate)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return ""
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, unixAgentVersionTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, candidate, "--version")
	cmd.Dir = home
	cmd.Env = []string{
		"HOME=" + home,
		"PATH=" + filepath.Dir(candidate) + ":/usr/bin:/bin",
		"LANG=C",
		"NO_COLOR=1",
		"TERM=dumb",
		"CI=1",
	}
	out := &cappedBuffer{limit: unixAgentVersionOutput}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = time.Second
	_ = cmd.Run()
	first, _, _ := strings.Cut(out.buf.String(), "\n")
	return ExtractUnixAgentVersion(first)
}
