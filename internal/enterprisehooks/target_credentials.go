// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

// TargetCredentials identifies one exact interactive user for a bounded
// privileged mutation. ACP enrollment reuses the hook guardian's per-target
// boundary (a worker process on Unix, SID impersonation on Windows) rather
// than granting the gateway user-home access.
type TargetCredentials struct {
	UserHome string
	UID      int
	GID      int
	SID      string
}

// RunAsTarget validates target identity and executes fn in this process with
// the target user's filesystem identity. Platform implementations fail closed
// when the process cannot prove the requested identity. On Unix fn runs only
// when the process already is the target user; a root caller must use
// RunTargetOperation instead.
func RunAsTarget(target TargetCredentials, fn func() error) error {
	return runAsTarget(target, fn)
}
