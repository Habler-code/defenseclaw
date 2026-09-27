//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/spf13/cobra"
)

// enterpriseHookWatchStopSignals are the signals launchd, systemd and an
// interactive terminal use to stop `enterprise hooks watch`.
var enterpriseHookWatchStopSignals = []os.Signal{syscall.SIGTERM, os.Interrupt}

// enterpriseHookWatchStopContext cancels the watch context on a stop signal
// so the watch loop returns and its deferred readiness retraction runs.
// Calling the returned function restores default signal handling, so a
// second signal after the loop has returned stops the process as before.
func enterpriseHookWatchStopContext(parent context.Context) (context.Context, context.CancelFunc) {
	if parent == nil {
		parent = context.Background()
	}
	return signal.NotifyContext(parent, enterpriseHookWatchStopSignals...)
}

var enterpriseHookSIDProfilePath = func(string) (string, error) {
	return "", fmt.Errorf("SID-only targets are supported only on native Windows")
}

func enterpriseHookDeferredTargetSessionAvailable(
	enterprisehooks.ManifestTarget,
) (bool, error) {
	return false, fmt.Errorf("deferred enterprise hook targets are supported only on native Windows")
}

func enterpriseHookTargetSessionAvailable(enterprisehooks.ManifestTarget) (bool, error) {
	return true, nil
}

// enterpriseHookTargetAwaitingFirstSignIn is Windows-only: other platforms
// have no per-SID session gate, so every failed target keeps withholding the
// enrollment publication exactly as before.
func enterpriseHookTargetAwaitingFirstSignIn(enterprisehooks.ManifestTarget) bool {
	return false
}

func stageEnterpriseHookDeferredManagedPolicies(
	enterprisehooks.Manifest,
	[]enterprisehooks.ManifestTarget,
	string,
	bool,
) error {
	return nil
}

func syncEnterpriseHookManagedEnrollments(
	enterprisehooks.Manifest,
	string,
	bool,
) error {
	return nil
}

func verifyEnterpriseHookManagedEnrollments(
	enterprisehooks.Manifest,
	string,
) error {
	return nil
}

func enterpriseHooksNativePlatformPreflight() error { return nil }

func enterpriseHooksNativeMutationIdentityPreflight() error { return nil }

func enterpriseHooksNativePersistentPreRun(cmd *cobra.Command, args []string) error {
	if cmd == enterpriseHooksStatusCmd {
		return enterpriseHooksConfigOnlyPersistentPreRun(cmd, args)
	}
	return enterpriseHooksFullRootPersistentPreRun(cmd, args)
}
