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
	"io"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// unixLifecycleOptions are the flags of `enterprise linux|macos <action>`.
type unixLifecycleOptions struct {
	payload              string
	fromPackage          bool
	config               string
	noStart              bool
	adoptExisting        bool
	allowDowngrade       bool
	purge                bool
	removeServiceAccount bool
	productVersion       string
	reason               string
	lockWait             time.Duration
	json                 bool
}

// enterpriseSecretOptions are the flags of `enterprise secret <action>`.
type enterpriseSecretOptions struct {
	name      string
	fromStdin bool
	fromFile  string
	json      bool
}

var (
	enterpriseLinuxCmd = newUnixLifecycleGroup("linux", "Linux (systemd)")
	enterpriseMacOSCmd = newUnixLifecycleGroup("macos", "macOS (launchd)")

	enterpriseSecretCmd = &cobra.Command{
		Use:   "secret",
		Short: "Manage protected credentials of a standalone managed deployment",
		Long: `Store, inspect or remove the protected credentials a standalone managed
deployment reads, such as the Cisco AI Defense API key named by
enterprise.inspection.ai_defense.credential.

Values are read from standard input or a file and are never printed.
Status shows only presence, modification time and a digest prefix.`,
		PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
	}
)

func newUnixLifecycleGroup(name, platform string) *cobra.Command {
	group := &cobra.Command{
		Use:   name,
		Short: "Manage the standalone managed-enterprise deployment on " + platform,
		Long: `Install, upgrade, repair, reconcile, inspect, verify or remove the standalone
managed-enterprise DefenseClaw deployment on ` + platform + `.

Every mutating action is a transaction: it takes the lifecycle lock,
snapshots what it will change, applies, activates the services in
dependency order, verifies, and rolls back on any failure. Run as root
from an administrator shell, a package script or an MDM agent.

Exit codes: 0 success or no-op, 1 failure (rolled back), 2 invalid
arguments, 75 another lifecycle run holds the lock.`,
		PersistentPreRunE: func(*cobra.Command, []string) error { return nil },
	}
	summaries := map[string]string{
		"install":   "Install the deployment (refuses when one is already installed)",
		"upgrade":   "Upgrade an installed deployment from a new payload or package",
		"repair":    "Re-apply the installed deployment's files, modes and services",
		"ensure":    "Install, upgrade or repair as needed; a no-op when nothing changed",
		"reconcile": "Run one immediate hook guardian reconcile",
		"status":    "Report the deployment state (read-only)",
		"verify":    "Verify every file, permission, service and readiness check (read-only)",
		"uninstall": "Stop and remove the deployment; --purge also removes config and state",
	}
	for _, action := range []string{"install", "upgrade", "repair", "ensure", "reconcile", "status", "verify", "uninstall"} {
		group.AddCommand(newUnixLifecycleCommand(name, action, summaries[action]))
	}
	return group
}

func newUnixLifecycleCommand(platform, action, summary string) *cobra.Command {
	opts := &unixLifecycleOptions{}
	cmd := &cobra.Command{
		Use:          action,
		Short:        summary,
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runUnixLifecycle(cmd, platform, action, opts)
		},
	}
	flags := cmd.Flags()
	switch action {
	case "install", "upgrade", "repair", "ensure":
		flags.StringVar(&opts.payload, "payload", "", "absolute directory holding the staged binaries to install")
		flags.BoolVar(&opts.fromPackage, "from-package", false, "use the binaries the defenseclaw-enterprise package installed")
		flags.StringVar(&opts.config, "config", "", "absolute path of the administrator config to install")
		flags.BoolVar(&opts.noStart, "no-start", false, "install without starting the services")
		flags.StringVar(&opts.productVersion, "product-version", "", "refuse unless the payload is exactly this version")
		flags.BoolVar(&opts.allowDowngrade, "allow-downgrade", false, "allow installing a version older than the installed one (deliberate rollback)")
		if action == "install" || action == "ensure" {
			flags.BoolVar(&opts.adoptExisting, "adopt-existing", false, "back up and take over an unmanaged DefenseClaw layout")
		}
		if action == "ensure" {
			flags.StringVar(&opts.reason, "reason", "", "why ensure runs (recorded in the result)")
		}
		flags.DurationVar(&opts.lockWait, "lock-wait", 0, "wait up to this long for another lifecycle run (default 5s, at most 15m) before exiting 75")
	case "uninstall":
		flags.BoolVar(&opts.purge, "purge", false, "also remove config, secrets, state and logs")
		flags.BoolVar(&opts.removeServiceAccount, "remove-service-account", false, "with --purge, also delete the gateway service account")
	}
	flags.BoolVar(&opts.json, "json", false, "print the lifecycle result as JSON")
	return cmd
}

func newEnterpriseSecretCommand(action, summary string) *cobra.Command {
	opts := &enterpriseSecretOptions{}
	cmd := &cobra.Command{
		Use:          action,
		Short:        summary,
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runEnterpriseSecret(cmd, action, opts)
		},
	}
	if action != "status" {
		cmd.Flags().StringVar(&opts.name, "name", "", "credential name (lowercase letters, digits and dashes)")
		_ = cmd.MarkFlagRequired("name")
	}
	if action == "set" {
		cmd.Flags().BoolVar(&opts.fromStdin, "from-stdin", false, "read the value from standard input")
		cmd.Flags().StringVar(&opts.fromFile, "from-file", "", "read the value from this file")
	}
	cmd.Flags().BoolVar(&opts.json, "json", false, "print JSON")
	return cmd
}

func init() {
	enterpriseSecretCmd.AddCommand(
		newEnterpriseSecretCommand("set", "Store a protected credential and apply it"),
		newEnterpriseSecretCommand("status", "List protected credentials without revealing values"),
		newEnterpriseSecretCommand("remove", "Remove a protected credential and apply the change"),
	)
	enterpriseCmd.AddCommand(enterpriseLinuxCmd, enterpriseMacOSCmd, enterpriseSecretCmd)
}

// writeLifecycleSummary prints a short human-readable result.
func writeLifecycleSummary(w io.Writer, action string, ok, noop bool, noopReason string, errs, warns []string) {
	switch {
	case ok && noop:
		fmt.Fprintf(w, "✓ %s: nothing to do (%s)\n", action, noopReason)
	case ok:
		fmt.Fprintf(w, "✓ %s: done\n", action)
	default:
		fmt.Fprintf(w, "✗ %s failed\n", action)
	}
	for _, warning := range warns {
		fmt.Fprintf(w, "  ! %s\n", warning)
	}
	for _, e := range errs {
		fmt.Fprintf(w, "  ✗ %s\n", e)
	}
}

func joinMessages(parts []string) string { return strings.Join(parts, "; ") }
