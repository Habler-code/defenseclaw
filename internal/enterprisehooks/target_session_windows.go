// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

func requireWindowsEnterpriseDeferredTargetPendingPlatform(target ManifestTarget) error {
	if !target.IsEnabled() || !target.IsDeferred() {
		return errors.New("enterprise hooks: pending proof requires an enabled deferred manifest target")
	}
	connectorName := strings.ToLower(strings.TrimSpace(target.Connector))
	switch connectorName {
	case "codex", "claudecode", "cursor":
	default:
		return fmt.Errorf(
			"enterprise hooks: deferred pending proof does not support connector %q",
			target.Connector,
		)
	}
	if connectorName == "claudecode" {
		if err := requireWindowsEnterpriseDeferredClaudePolicyStageable(target); err != nil {
			return err
		}
	}
	home, targetSID, err := validateWindowsEnterpriseHome(target.UserHome, target.SID)
	if err != nil {
		return err
	}
	dataDir, err := resolveWindowsEnterpriseDataDir(home, target.DataDir)
	if err != nil {
		return err
	}
	if err := validateWindowsUserPathElement(dataDir, targetSID, true, true, true); err != nil {
		return fmt.Errorf(
			"enterprise hooks: deferred target data directory is untrusted: %w",
			err,
		)
	}
	hookExecutable, err := windowsEnterpriseHookExecutable()
	if err != nil {
		return err
	}
	hookExecutable = filepath.Clean(hookExecutable)
	if err := windowsEnterpriseHookTrustCheck(hookExecutable); err != nil {
		return fmt.Errorf(
			"enterprise hooks: deferred target hook executable trust check failed: %w",
			err,
		)
	}
	return verifyWindowsManagedRuntimeSelectorTargetAbsentPlatform(
		WindowsManagedRuntimeSelectorSnapshotOptions{
			Connector:      connectorName,
			TargetSID:      targetSID.String(),
			DataDir:        dataDir,
			HookExecutable: hookExecutable,
		},
	)
}

// windowsDeferredClaudePolicyTargetsReader reads the SIDs the Claude Code
// machine policy already covers (the set deferred staging skips). Tests
// replace it.
var windowsDeferredClaudePolicyTargetsReader = ReadWindowsClaudeManagedPolicyTargets

// requireWindowsEnterpriseDeferredClaudePolicyStageable proves that deferred
// staging can cover a Claude Code target. Staging renders the machine policy
// from the row's recorded agent_version, and a version below the enrollment
// floor has no hook contract to render. Such a row still loads (an earlier
// release often recorded it as the placeholder for a user with no detected
// client), so without this check it was reported pending and then failed
// staging, which rolled back staging for every other pending SID and withheld
// the exact enrollment publication (#894). The row stays pending only when an
// earlier release already staged its SID, because staging then skips it and
// has nothing to render. Otherwise it is not pending: it fails as its own
// target, and while its user is signed out it is one of the targets awaiting
// first sign-in that do not withhold staging or publication for other SIDs.
func requireWindowsEnterpriseDeferredClaudePolicyStageable(target ManifestTarget) error {
	versionErr := requireWindowsEnterpriseManagedAgentVersion("claudecode", target.AgentVersion)
	if versionErr == nil {
		return nil
	}
	sid, err := validateWindowsEnterpriseTargetSID(target.SID)
	if err != nil {
		return err
	}
	staged, _, err := windowsDeferredClaudePolicyTargetsReader()
	if err != nil {
		return fmt.Errorf(
			"enterprise hooks: deferred Claude Code machine policy cannot be staged for this target: %w (read the staged Claude Code targets: %v)",
			versionErr,
			err,
		)
	}
	for _, stagedSID := range staged {
		if strings.EqualFold(strings.TrimSpace(stagedSID), sid.String()) {
			return nil
		}
	}
	return fmt.Errorf(
		"enterprise hooks: deferred Claude Code machine policy cannot be staged for this target: %w",
		versionErr,
	)
}

func requireWindowsEnterpriseTargetUnselectedPlatform(target ManifestTarget) error {
	if !target.IsEnabled() {
		return errors.New("enterprise hooks: selection proof requires an enabled manifest target")
	}
	connectorName := strings.ToLower(strings.TrimSpace(target.Connector))
	switch connectorName {
	case "codex", "claudecode", "cursor":
	default:
		return fmt.Errorf(
			"enterprise hooks: selection proof does not support connector %q",
			target.Connector,
		)
	}
	_, targetSID, err := validateWindowsEnterpriseHome(target.UserHome, target.SID)
	if err != nil {
		return err
	}
	selector, _, exists, err := readWindowsManagedRuntimeSelector(connectorName, true)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}
	if _, selected := windowsManagedRuntimeSelectorTargetForSID(selector, targetSID.String()); selected {
		return errors.New("enterprise hooks: target already has a selected managed runtime")
	}
	return nil
}
