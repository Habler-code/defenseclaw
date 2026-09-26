// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

// StageWindowsEnterpriseDeferredPolicies activates the token-free protected
// machine-policy envelope for manifest-authorized pending rows. It never
// creates or repairs target-owned runtime; that still requires the exact
// user's WTS token in Install. claudeCodeAllowUnmanagedHooks is the
// administrator's claude_code.allow_unmanaged_hooks setting; see
// deferredClaudeCodeAllowUnmanagedHooks for when staging applies it.
func StageWindowsEnterpriseDeferredPolicies(
	manifest Manifest,
	pending []ManifestTarget,
	apiAddr string,
	claudeCodeAllowUnmanagedHooks bool,
) error {
	return stageWindowsEnterpriseDeferredPoliciesPlatform(
		manifest,
		pending,
		apiAddr,
		claudeCodeAllowUnmanagedHooks,
	)
}

// deferredClaudeCodeAllowUnmanagedHooks picks the managed-hooks-only lock
// state that deferred staging renders into the Claude Code policy and admits
// an outranking OS-admin (HKLM) policy with. Staging a SID into an active
// DefenseClaw Claude Code policy must not change that machine-wide policy's
// lock state, so the published state is kept. When no policy is active yet,
// staging publishes the first one (every Claude Code target is still waiting
// for its user's first sign-in) and follows the administrator's
// configuration, as the install of a signed-in target does.
func deferredClaudeCodeAllowUnmanagedHooks(
	policyActive bool,
	configured bool,
	published func() (bool, error),
) (bool, error) {
	if !policyActive {
		return configured, nil
	}
	return published()
}
