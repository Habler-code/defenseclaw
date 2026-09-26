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
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// The standalone Unix enumerator: the Linux and macOS counterpart of the
// Windows ProfileList enumerator. It discovers eligible interactive users
// and publishes the guardian manifest, preserving the protected enabled /
// deferred / version state of rows it already knows.

// UnixRevokeAfterMisses is how many consecutive definitive "no such user"
// answers remove a known row. Transient directory errors never count.
const UnixRevokeAfterMisses = 3

// unixNologinShells are login shells that mark a non-interactive account.
var unixNologinShells = map[string]struct{}{
	"/usr/sbin/nologin": {}, "/sbin/nologin": {}, "/usr/bin/nologin": {},
	"/bin/false": {}, "/usr/bin/false": {}, "/sbin/false": {},
}

// UnixEnumeratorState is persisted between cycles (root-only) so revocation
// needs several definitive misses.
type UnixEnumeratorState struct {
	Version int            `json:"version"`
	Misses  map[string]int `json:"misses,omitempty"`
}

// UnixDiscoverFunc returns connector → version for one account, discovered
// with that account's credentials (the apply-target worker). reasons
// explains connectors without a version.
type UnixDiscoverFunc func(ctx context.Context, account unixidentity.Account, connectors []string) (versions map[string]string, reasons map[string]string, err error)

// UnixEnumerateOptions configures one enumeration cycle. Zero values pick
// the platform defaults.
type UnixEnumerateOptions struct {
	ExistingManifestPath string
	Resolver             unixidentity.Resolver
	// HomeRoots are the parents homes must live under (default /home,
	// /var/home on Linux; /Users on macOS) plus enrollment.home_roots.
	HomeRoots []string
	// UIDMin/UIDMax bound interactive accounts (default login.defs).
	UIDMin, UIDMax int
	// MachinePolicyConnectors come from the runtime descriptor; they get
	// per-user rows only when enrollment.unenrolled_users is "deny".
	MachinePolicyConnectors []string
	// SessionUIDs lists uids with a live login session.
	SessionUIDs func() []int
	Discover    UnixDiscoverFunc
	// MachineVersion reads root-owned machine-scoped metadata.
	MachineVersion func(connector string) string
	State          *UnixEnumeratorState
	Logger         EnumerationLogger
}

// UnixEnumerationReport summarizes a cycle for logs and JSON output.
type UnixEnumerationReport struct {
	Candidates int      `json:"candidates"`
	Eligible   int      `json:"eligible"`
	Rows       int      `json:"rows"`
	New        int      `json:"new"`
	Deferred   int      `json:"deferred"`
	Revoked    int      `json:"revoked"`
	Skipped    []string `json:"skipped,omitempty"`
	Connectors []string `json:"connectors"`
}

type unixCandidate struct {
	account  unixidentity.Account
	included bool
}

// DefaultUnixHomeRoots are the home parents the guardian units allow.
func DefaultUnixHomeRoots(goos string) []string {
	if goos == "darwin" {
		return []string{"/Users"}
	}
	return []string{"/home", "/var/home"}
}

// EffectiveUnixHookConnectors returns the enabled hook-owning connectors
// for per-user enrollment on this host, in sorted order.
func EffectiveUnixHookConnectors(cfg *config.Config, registry *connector.Registry) []string {
	if cfg == nil || registry == nil {
		return nil
	}
	disabled := map[string]struct{}{}
	seen := map[string]struct{}{}
	var out []string
	consider := func(name string, explicitlyDisabled bool) {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			return
		}
		if explicitlyDisabled {
			disabled[name] = struct{}{}
			return
		}
		if _, off := disabled[name]; off {
			return
		}
		if _, dup := seen[name]; dup {
			return
		}
		conn, ok := registry.Get(name)
		if !ok || connector.IsProxyConnector(name) || !connector.OwnsManagedHookRuntime(conn) ||
			!connector.ConnectorSupportedOnHostOS(name) {
			return
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	for name, perConn := range cfg.Guardrail.Connectors {
		consider(name, perConn.Enabled != nil && !*perConn.Enabled)
	}
	consider(cfg.Guardrail.Connector, false)
	sort.Strings(out)
	return out
}

// EnumerateUnix discovers eligible users and returns the manifest to
// publish. It never writes; WriteUnixTargetsManifestAtomic publishes.
func EnumerateUnix(ctx context.Context, cfg *config.Config, registry *connector.Registry, opts UnixEnumerateOptions) (Manifest, UnixEnumerationReport, error) {
	report := UnixEnumerationReport{}
	if cfg == nil {
		return Manifest{}, report, errors.New("enterprise hooks: enumerate: nil config")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if opts.Resolver == nil {
		return Manifest{}, report, errors.New("enterprise hooks: enumerate: no account resolver")
	}
	if opts.State == nil {
		opts.State = &UnixEnumeratorState{Version: 1}
	}
	if opts.State.Misses == nil {
		opts.State.Misses = map[string]int{}
	}
	enrollment := cfg.Enterprise.Enrollment
	connectors := EffectiveUnixHookConnectors(cfg, registry)
	machinePolicy := map[string]struct{}{}
	for _, name := range opts.MachinePolicyConnectors {
		machinePolicy[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
	}
	var perUser []string
	for _, name := range connectors {
		if _, isMachine := machinePolicy[name]; isMachine &&
			!strings.EqualFold(strings.TrimSpace(enrollment.UnenrolledUsers), config.EnterpriseUnenrolledDeny) {
			continue
		}
		perUser = append(perUser, name)
	}
	report.Connectors = perUser

	previous := loadPreviousUnixRows(opts.ExistingManifestPath, opts.Logger)
	uidMin, uidMax := opts.UIDMin, opts.UIDMax
	if enrollment.UIDMin > 0 {
		uidMin = enrollment.UIDMin
	}
	homeRoots := normalizeHomeRoots(opts.HomeRoots)

	candidates, _ := collectUnixCandidates(ctx, opts, enrollment, homeRoots)
	// Re-evaluate every previously enrolled user even when enumeration did
	// not surface it (SSSD enumerate=false, a logged-out user), so a known
	// row is only dropped by a filter decision or repeated definitive
	// "no such user" answers — never by an incomplete listing.
	keep := map[string]struct{}{}
	missing := map[string]struct{}{}
	listed := map[string]struct{}{}
	previousUsers := map[string]struct{}{}
	for _, prev := range previous {
		previousUsers[strings.TrimSpace(prev.User)] = struct{}{}
	}
	for _, candidate := range candidates {
		listed[candidate.account.Name] = struct{}{}
	}
	for _, prev := range previous {
		userName := strings.TrimSpace(prev.User)
		if _, ok := listed[userName]; ok || userName == "" {
			continue
		}
		listed[userName] = struct{}{}
		account, err := opts.Resolver.LookupUser(userName)
		switch {
		case err == nil:
			candidates = append(candidates, unixCandidate{account: account})
		case unixidentity.IsNotFound(err):
			missing[userName] = struct{}{}
		default:
			keep[userName] = struct{}{}
			logfSafely(opts.Logger, userName, fmt.Sprintf("directory lookup failed; keeping known rows unchanged: %v", err))
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].account.Name < candidates[j].account.Name })
	report.Candidates = len(candidates)
	include := stringSet(enrollment.IncludeUsers)
	exclude := stringSet(enrollment.ExcludeUsers)
	exempt := stringSet(enrollment.ExemptUsers)

	var targets []ManifestTarget
	emitted := map[string]struct{}{}
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return Manifest{}, report, err
		}
		account := candidate.account
		name := account.Name
		skip := func(reason string) {
			report.Skipped = append(report.Skipped, name+": "+reason)
			logfSafely(opts.Logger, name, reason)
		}
		if _, ok := exclude[name]; ok {
			skip("excluded by enterprise.enrollment.exclude_users")
			continue
		}
		if _, ok := exempt[name]; ok {
			skip("exempt by enterprise.enrollment.exempt_users")
			continue
		}
		_, explicitlyIncluded := include[name]
		if account.UID == 0 {
			skip("root is never a guardian target")
			continue
		}
		if account.UID == 65534 || name == "nobody" {
			skip("nobody is never a guardian target")
			continue
		}
		if !explicitlyIncluded && (account.UID < uidMin || (uidMax > 0 && account.UID > uidMax)) {
			skip(fmt.Sprintf("uid %d outside the interactive range %d-%d", account.UID, uidMin, uidMax))
			continue
		}
		if _, nologin := unixNologinShells[filepath.Clean(account.Shell)]; nologin && !explicitlyIncluded {
			skip("non-interactive login shell " + account.Shell)
			continue
		}
		if ok, transientErr, reason := groupFilterAllows(opts.Resolver, account, enrollment); !ok {
			if transientErr {
				keep[name] = struct{}{}
			}
			skip(reason)
			continue
		}
		home := filepath.Clean(account.Home)
		if !homeUnderRoots(home, homeRoots) {
			skip(fmt.Sprintf("home %s is outside the guardian-writable home roots %v", home, homeRoots))
			continue
		}
		check := CheckUnixTargetHome(home, account.UID)
		if check.State == HomeUntrusted {
			if _, enrolled := previousUsers[name]; enrolled {
				// A user must not unenroll themselves by loosening their
				// own home's mode: keep the rows so the guardian reports
				// the trust failure instead of silently dropping them.
				keep[name] = struct{}{}
				skip(check.Reason + "; keeping the existing enrollment")
				continue
			}
			skip(check.Reason)
			continue
		}
		report.Eligible++
		var versions, reasons map[string]string
		if check.State == HomeAvailable && opts.Discover != nil {
			var err error
			versions, reasons, err = opts.Discover(ctx, account, perUser)
			if err != nil {
				logfSafely(opts.Logger, name, fmt.Sprintf("version discovery failed; keeping known rows: %v", err))
			}
		}
		for _, conn := range perUser {
			key := unixRowKey(name, conn)
			row := ManifestTarget{
				User:      name,
				UserHome:  home,
				UID:       intPointer(account.UID),
				GID:       intPointer(account.GID),
				Connector: conn,
				DataDir:   filepath.Join(home, ".defenseclaw"),
				HomeInode: check.Inode,
			}
			if prev, known := previous[key]; known && sameUnixIdentity(prev, row) {
				row.AgentVersion = prev.AgentVersion
				row.Enabled = prev.Enabled
				if check.State == HomeAvailable {
					if version := versions[conn]; version != "" && prev.IsEnabled() {
						row.AgentVersion = version
					}
					row.Deferred = false
				} else {
					row.Deferred = prev.IsEnabled()
					row.HomeInode = prev.HomeInode
				}
				targets = append(targets, row)
				emitted[key] = struct{}{}
				continue
			} else if known {
				logfSafely(opts.Logger, name, fmt.Sprintf("uid or home changed for (%s, %s); re-enrolling as a new target", name, conn))
			}
			version := versions[conn]
			if check.State != HomeAvailable && opts.MachineVersion != nil {
				version = opts.MachineVersion(conn)
			}
			if version == "" {
				reason := reasons[conn]
				if reason == "" {
					reason = "no supported installation found"
				}
				if check.State != HomeAvailable {
					reason = check.Reason
				}
				logfSafely(opts.Logger, name, fmt.Sprintf("new (%s, %s) row skipped: %s", name, conn, reason))
				continue
			}
			enabled := true
			row.AgentVersion = version
			row.Enabled = &enabled
			row.Deferred = check.State != HomeAvailable
			if row.Deferred {
				report.Deferred++
			}
			report.New++
			targets = append(targets, row)
			emitted[key] = struct{}{}
		}
	}

	// Known rows that were not re-emitted: keep them through transient
	// failures, count definitive misses, and revoke only after
	// UnixRevokeAfterMisses consecutive "no such user" answers or an
	// explicit filter decision.
	for key, prev := range previous {
		if _, ok := emitted[key]; ok {
			delete(opts.State.Misses, key)
			continue
		}
		if !connectorListed(perUser, prev.Connector) {
			// The connector is no longer enabled for per-user enrollment.
			delete(opts.State.Misses, key)
			report.Revoked++
			continue
		}
		userName := strings.TrimSpace(prev.User)
		if _, transientErr := keep[userName]; transientErr {
			targets = append(targets, prev)
			continue
		}
		if _, gone := missing[userName]; gone {
			opts.State.Misses[key]++
			if opts.State.Misses[key] < UnixRevokeAfterMisses {
				logfSafely(opts.Logger, userName, fmt.Sprintf("account not found (%d/%d); keeping (%s, %s) for now", opts.State.Misses[key], UnixRevokeAfterMisses, userName, prev.Connector))
				targets = append(targets, prev)
				continue
			}
			logfSafely(opts.Logger, userName, fmt.Sprintf("account not found %d times; revoking (%s, %s)", UnixRevokeAfterMisses, userName, prev.Connector))
		}
		delete(opts.State.Misses, key)
		report.Revoked++
	}
	for key := range opts.State.Misses {
		if _, known := previous[key]; !known {
			delete(opts.State.Misses, key)
		}
	}

	sort.Slice(targets, func(i, j int) bool {
		if targets[i].User != targets[j].User {
			return targets[i].User < targets[j].User
		}
		return targets[i].Connector < targets[j].Connector
	})
	report.Rows = len(targets)
	if targets == nil {
		targets = []ManifestTarget{}
	}
	return Manifest{Version: 1, Targets: targets}, report, nil
}

func collectUnixCandidates(ctx context.Context, opts UnixEnumerateOptions, enrollment config.EnterpriseEnrollmentConfig, homeRoots []string) ([]unixCandidate, bool) {
	byName := map[string]*unixCandidate{}
	transient := false
	add := func(account unixidentity.Account, included bool) {
		if existing, ok := byName[account.Name]; ok {
			existing.included = existing.included || included
			return
		}
		byName[account.Name] = &unixCandidate{account: account, included: included}
	}
	if accounts, _, err := opts.Resolver.ListUsers(); err == nil {
		for _, account := range accounts {
			add(account, false)
		}
	} else {
		transient = true
		logfSafely(opts.Logger, "directory", fmt.Sprintf("account enumeration failed: %v", err))
	}
	resolveUID := func(uid int, source string) {
		account, err := opts.Resolver.LookupUID(uid)
		if err != nil {
			if !unixidentity.IsNotFound(err) {
				transient = true
			}
			logfSafely(opts.Logger, strconv.Itoa(uid), fmt.Sprintf("%s uid did not resolve: %v", source, err))
			return
		}
		add(account, false)
	}
	if opts.SessionUIDs != nil {
		for _, uid := range opts.SessionUIDs() {
			resolveUID(uid, "session")
		}
	}
	for _, root := range homeRoots {
		entries, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if ctx.Err() != nil {
				break
			}
			info, err := os.Lstat(filepath.Join(root, entry.Name()))
			if err != nil || !info.IsDir() {
				continue
			}
			st, ok := info.Sys().(*syscall.Stat_t)
			if !ok || st.Uid == 0 {
				continue
			}
			resolveUID(int(st.Uid), "home owner")
		}
	}
	for _, name := range enrollment.IncludeUsers {
		account, err := opts.Resolver.LookupUser(strings.TrimSpace(name))
		if err != nil {
			if !unixidentity.IsNotFound(err) {
				transient = true
			}
			logfSafely(opts.Logger, name, fmt.Sprintf("included user did not resolve: %v", err))
			continue
		}
		add(account, true)
	}
	out := make([]unixCandidate, 0, len(byName))
	for _, candidate := range byName {
		out = append(out, *candidate)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].account.Name < out[j].account.Name })
	return out, transient
}

// groupFilterAllows applies include/exclude groups (exclude wins). A
// transient membership failure reports transient=true so known rows stay.
func groupFilterAllows(resolver unixidentity.Resolver, account unixidentity.Account, enrollment config.EnterpriseEnrollmentConfig) (allowed bool, transient bool, reason string) {
	if len(enrollment.IncludeGroups) == 0 && len(enrollment.ExcludeGroups) == 0 {
		return true, false, ""
	}
	ids, err := resolver.GroupIDs(account)
	if err != nil {
		return false, !unixidentity.IsNotFound(err), fmt.Sprintf("group membership unavailable: %v", err)
	}
	names := map[string]struct{}{}
	for _, gid := range ids {
		names[strconv.Itoa(gid)] = struct{}{}
		if group, err := resolver.LookupGroupID(gid); err == nil {
			names[group.Name] = struct{}{}
		}
	}
	for _, excluded := range enrollment.ExcludeGroups {
		if _, ok := names[strings.TrimSpace(excluded)]; ok {
			return false, false, "member of excluded group " + excluded
		}
	}
	if len(enrollment.IncludeGroups) == 0 {
		return true, false, ""
	}
	for _, included := range enrollment.IncludeGroups {
		if _, ok := names[strings.TrimSpace(included)]; ok {
			return true, false, ""
		}
	}
	return false, false, "not a member of any enterprise.enrollment.include_groups group"
}

func loadPreviousUnixRows(path string, logf EnumerationLogger) map[string]ManifestTarget {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	manifest, err := LoadManifest(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			logfSafely(logf, path, fmt.Sprintf("existing manifest failed to load; treating every row as new: %v", err))
		}
		return nil
	}
	previous := make(map[string]ManifestTarget, len(manifest.Targets))
	for _, target := range manifest.Targets {
		if key := unixRowKey(target.User, target.Connector); key != "" {
			previous[key] = target
		}
	}
	return previous
}

func unixRowKey(user, conn string) string {
	user = strings.TrimSpace(user)
	conn = strings.ToLower(strings.TrimSpace(conn))
	if user == "" || conn == "" {
		return ""
	}
	return user + "\x00" + conn
}

// sameUnixIdentity reports whether a previous row still names the same
// account and home. A different uid, or a different inode for a home
// that exists, is a reused or recreated identity.
func sameUnixIdentity(prev, current ManifestTarget) bool {
	if prev.UID == nil || current.UID == nil || *prev.UID != *current.UID {
		return false
	}
	if filepath.Clean(prev.UserHome) != filepath.Clean(current.UserHome) {
		return false
	}
	if prev.HomeInode != 0 && current.HomeInode != 0 && prev.HomeInode != current.HomeInode {
		return false
	}
	return true
}

func normalizeHomeRoots(roots []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, root := range roots {
		root = filepath.Clean(strings.TrimSpace(root))
		if root == "" || !filepath.IsAbs(root) || root == "/" {
			continue
		}
		if _, dup := seen[root]; dup {
			continue
		}
		seen[root] = struct{}{}
		out = append(out, root)
	}
	sort.Strings(out)
	return out
}

func homeUnderRoots(home string, roots []string) bool {
	for _, root := range roots {
		if rel, err := filepath.Rel(root, home); err == nil && rel != "." && rel != ".." &&
			!strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func connectorListed(list []string, name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, candidate := range list {
		if candidate == name {
			return true
		}
	}
	return false
}

func stringSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			out[value] = struct{}{}
		}
	}
	return out
}

func intPointer(value int) *int { return &value }

// MarshalUnixTargetsManifest renders the deterministic manifest bytes.
func MarshalUnixTargetsManifest(m Manifest) ([]byte, error) {
	if m.Version == 0 {
		m.Version = 1
	}
	if m.Targets == nil {
		m.Targets = []ManifestTarget{}
	}
	raw, err := yaml.Marshal(&m)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: marshal manifest: %w", err)
	}
	return raw, nil
}

// WriteUnixTargetsManifestAtomic publishes m at path when its bytes change:
// root-owned 0640 file below a root-owned directory chain with no symlinks
// or group/other-writable elements, written through a same-directory temp
// file, fsync and rename. A byte-identical manifest is not rewritten, so a
// stable host never wakes the guardian's file watch.
func WriteUnixTargetsManifestAtomic(path string, m Manifest) (bool, error) {
	path = filepath.Clean(strings.TrimSpace(path))
	if !filepath.IsAbs(path) {
		return false, fmt.Errorf("enterprise hooks: write targets manifest: path must be absolute: %s", path)
	}
	dir := filepath.Dir(path)
	if err := validateRootOwnedDirChain(dir); err != nil {
		return false, err
	}
	data, err := MarshalUnixTargetsManifest(m)
	if err != nil {
		return false, err
	}
	if info, statErr := os.Lstat(path); statErr == nil {
		if !info.Mode().IsRegular() {
			return false, fmt.Errorf("enterprise hooks: existing manifest %s is not a regular file", path)
		}
		current, readErr := readBoundedFile(path, enterpriseHookManifestMaxBytes)
		if readErr == nil && bytes.Equal(current, data) {
			return false, nil
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return false, fmt.Errorf("enterprise hooks: inspect manifest %s: %w", path, statErr)
	}
	tmp, err := os.CreateTemp(dir, ".defenseclaw-targets-*.new")
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: create temp manifest: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("enterprise hooks: write temp manifest: %w", err)
	}
	if err := tmp.Chmod(0o640); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("enterprise hooks: chmod temp manifest: %w", err)
	}
	if os.Geteuid() == 0 {
		if err := tmp.Chown(0, 0); err != nil {
			_ = tmp.Close()
			return false, fmt.Errorf("enterprise hooks: chown temp manifest: %w", err)
		}
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return false, fmt.Errorf("enterprise hooks: sync temp manifest: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return false, fmt.Errorf("enterprise hooks: close temp manifest: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return false, fmt.Errorf("enterprise hooks: publish manifest: %w", err)
	}
	if dirHandle, err := os.Open(dir); err == nil {
		_ = dirHandle.Sync()
		_ = dirHandle.Close()
	}
	return true, nil
}

// validateRootOwnedDirChain requires dir and every ancestor to be a real
// directory owned by root and not group/other writable.
func validateRootOwnedDirChain(dir string) error {
	for current := filepath.Clean(dir); ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("enterprise hooks: inspect manifest directory %s: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("enterprise hooks: manifest directory element %s is not a real directory", current)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("enterprise hooks: manifest directory element %s is group/other writable", current)
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || (st.Uid != 0 && !unixManifestTestOwnerAllowed(st.Uid)) {
			return fmt.Errorf("enterprise hooks: manifest directory element %s is not root-owned", current)
		}
		if current == filepath.Dir(current) {
			return nil
		}
	}
}

// unixManifestTestOwnerAllowed lets unprivileged tests publish into their
// own temp directories; production runs as root, where it is never used.
var unixManifestTestOwnerAllowed = func(uid uint32) bool { return false }

func readBoundedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	return data, nil
}

// LoadUnixEnumeratorState reads the root-only enumerator state; a missing
// or malformed file starts fresh (the worst case is a slower revocation).
func LoadUnixEnumeratorState(path string) *UnixEnumeratorState {
	state := &UnixEnumeratorState{Version: 1, Misses: map[string]int{}}
	data, err := readBoundedFile(path, 1<<20)
	if err != nil {
		return state
	}
	var parsed UnixEnumeratorState
	if json.Unmarshal(data, &parsed) != nil || parsed.Version != 1 {
		return state
	}
	for key, count := range parsed.Misses {
		if count > 0 && count < 1000 {
			state.Misses[key] = count
		}
	}
	return state
}

// SaveUnixEnumeratorState writes the state atomically, root-only 0600.
func SaveUnixEnumeratorState(path string, state *UnixEnumeratorState) error {
	if state == nil {
		return nil
	}
	state.Version = 1
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".defenseclaw-enumerator-*.new")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := tmp.Write(append(data, '\n')); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}
