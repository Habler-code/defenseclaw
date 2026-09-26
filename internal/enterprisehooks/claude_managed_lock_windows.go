// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// currentWindowsClaudeManagedPolicyAllowsUnmanagedHooks returns the lock state
// of the active machine-wide Claude Code policy. Deferred staging only adds a
// SID to that shared policy and has no administrator configuration of its own,
// so it keeps the published lock state instead of resetting an opt-out. A
// missing policy reports the secure default (locked).
func currentWindowsClaudeManagedPolicyAllowsUnmanagedHooks() (bool, error) {
	allow := false
	err := windowsClaudeManagedPolicyTransaction(func() error {
		path, err := windowsClaudeManagedPolicyPath()
		if err != nil {
			return err
		}
		if err := windowsManagedPolicyFileTrustCheckIfExists(path); err != nil {
			return err
		}
		policy, err := snapshotWindowsManagedFileWithLimit(path, windowsClaudeManagedPolicyLimit)
		if err != nil {
			return err
		}
		if !policy.existed {
			return nil
		}
		locked, err := connector.ClaudeCodeManagedHookPolicyEnforcesManagedOnly(policy.data)
		if err != nil {
			return fmt.Errorf("enterprise hooks: inspect Claude Code managed hooks-only lock: %w", err)
		}
		allow = !locked
		return nil
	})
	return allow, err
}

func windowsManagedPolicyFileTrustCheckIfExists(path string) error {
	if !windowsPathExists(path) {
		return nil
	}
	if err := windowsManagedPolicyFileTrustCheck(path); err != nil {
		return fmt.Errorf("enterprise hooks: untrusted Claude Code managed policy %s: %w", path, err)
	}
	return nil
}
