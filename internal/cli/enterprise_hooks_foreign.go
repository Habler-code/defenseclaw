// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// enterpriseForeignHookCleanup removes unapproved foreign hooks from one
// enrolled user's USER-level config for one connector on the standalone
// profile (backups under ~/.defenseclaw/foreign-hooks-backup). It runs as
// the user through RunAsTarget. The reconcile loop calls it after a
// per-user row verifies; the enumerator must call it for machine-policy
// connectors (which have no per-user manifest rows) once per eligible
// user. Secure Client and unmanaged configs return immediately.
// Replaceable in tests.
var enterpriseForeignHookCleanup = func(target enterprisehooks.TargetCredentials, connectorName, dataDir string) (enterprisepolicy.CleanupResult, error) {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return enterprisepolicy.CleanupResult{}, nil
	}
	name := strings.ToLower(strings.TrimSpace(connectorName))
	layout, programFiles, programData, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		return enterprisepolicy.CleanupResult{}, err
	}
	opts, err := enterprisepolicy.StandaloneOptions(layout, programFiles, programData, cfg)
	if err != nil {
		return enterprisepolicy.CleanupResult{}, err
	}
	policy := enterprisepolicy.BuildPublicPolicy(opts, []string{name}).Connectors[name]
	if !policy.Guard || policy.ForeignHooks != config.ForeignHooksRemove {
		return enterprisepolicy.CleanupResult{}, nil
	}
	request := enterprisepolicy.GuardRequest{
		Connector:     name,
		GOOS:          layout.GOOS,
		Home:          target.UserHome,
		HookBinary:    opts.HookBinary,
		Policy:        policy,
		OwnedCommands: perUserOwnedHookCommands(name, target.UserHome, dataDir),
	}
	var result enterprisepolicy.CleanupResult
	err = enterprisehooks.RunAsTarget(target, func() error {
		var cleanErr error
		result, cleanErr = enterprisepolicy.CleanUserForeignHooks(request, time.Now())
		return cleanErr
	})
	return result, err
}

// reconcileEnterpriseForeignHooks is the reconcile loop's call site. Cleanup
// is best effort: the admin-owned hook still denies tool calls while an
// unapproved hook remains, so a failure here never fails the row.
func reconcileEnterpriseForeignHooks(opts enterprisehooks.InstallOptions) {
	result, err := enterpriseForeignHookCleanup(enterprisehooks.TargetCredentials{
		UserHome: opts.UserHome,
		UID:      opts.OwnerUID,
		GID:      opts.OwnerGID,
		SID:      opts.OwnerSID,
	}, opts.ConnectorName, opts.DataDir)
	for _, finding := range result.Removed {
		fmt.Fprintf(os.Stderr, "defenseclaw: enterprise foreign-hook guard: removed %s %s hook from %s (sha256:%s); backup in %s\n",
			finding.Connector, dashIfEmpty(finding.Event), finding.Path, finding.Digest, result.BackupDir)
	}
	for _, finding := range result.Reported {
		fmt.Fprintf(os.Stderr, "defenseclaw: enterprise foreign-hook guard: %s hook in %s left in place (%s)\n", finding.Connector, finding.Path, finding.Reason)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "defenseclaw: enterprise foreign-hook guard: cleanup for %s %s: %v\n", opts.ConnectorName, opts.UserHome, err)
	}
}
