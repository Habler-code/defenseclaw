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

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
)

// newUnixLifecycleEnv is a seam for CLI tests.
var newUnixLifecycleEnv = func(goos string) (*enterpriseunix.Env, error) {
	return enterpriseunix.NewEnv(goos, appVersion)
}

func platformGOOS(platform string) string {
	if platform == "macos" {
		return "darwin"
	}
	return platform
}

func runUnixLifecycle(cmd *cobra.Command, platform, action string, opts *unixLifecycleOptions) error {
	goos := platformGOOS(platform)
	if enterpriseunix.CurrentGOOS() != goos {
		return withExitCode(fmt.Errorf("`enterprise %s` manages %s hosts; this host is %s", platform, goos, enterpriseunix.CurrentGOOS()), enterprisestatus.UnixExitInvalidArgs)
	}
	if opts.lockWait < 0 || opts.lockWait > enterpriseunix.MaxLockWait {
		return withExitCode(fmt.Errorf("--lock-wait must be between 0 and %s", enterpriseunix.MaxLockWait), enterprisestatus.UnixExitInvalidArgs)
	}
	env, err := newUnixLifecycleEnv(goos)
	if err != nil {
		return withExitCode(err, enterprisestatus.UnixExitFailure)
	}
	if opts.lockWait > 0 {
		env.LockTimeout = opts.lockWait
	}
	result := enterpriseunix.Run(cmd.Context(), env, enterpriseunix.Options{
		Action:               action,
		PayloadDir:           opts.payload,
		FromPackage:          opts.fromPackage,
		ConfigFile:           opts.config,
		NoStart:              opts.noStart,
		AdoptExisting:        opts.adoptExisting,
		Purge:                opts.purge,
		RemoveServiceAccount: opts.removeServiceAccount,
		ProductVersion:       opts.productVersion,
		Reason:               opts.reason,
	})
	if err := printLifecycleResult(cmd.OutOrStdout(), result, opts.json); err != nil {
		return err
	}
	if result.OK {
		return nil
	}
	return withExitCode(errors.New(lifecycleErrorSummary(result)), result.ExitCode)
}

func printLifecycleResult(w io.Writer, result *enterprisestatus.Result, asJSON bool) error {
	if asJSON {
		encoder := json.NewEncoder(w)
		encoder.SetIndent("", "  ")
		return encoder.Encode(result)
	}
	var errs, warns []string
	for _, e := range result.Errors {
		errs = append(errs, e.Code+": "+e.Message)
	}
	for _, warning := range result.Warnings {
		warns = append(warns, warning.Code+": "+warning.Message)
	}
	writeLifecycleSummary(w, result.Action, result.OK, result.Noop, result.NoopReason, errs, warns)
	if result.Action == enterpriseunix.ActionStatus || result.Action == enterpriseunix.ActionVerify {
		fmt.Fprintf(w, "  installed=%v version=%s gateway_ready=%v guardian_ready=%v enumerator_ready=%v sensor_helper_ready=%v\n",
			result.Installed, result.InstalledVersion, result.Readiness.Gateway, result.Readiness.Guardian,
			result.Readiness.Enumerator, result.Readiness.SensorHelper)
		for _, service := range result.Services {
			fmt.Fprintf(w, "  %-46s %s\n", service.Name, service.State)
		}
	}
	return nil
}

func lifecycleErrorSummary(result *enterprisestatus.Result) string {
	parts := make([]string, 0, len(result.Errors))
	for _, e := range result.Errors {
		parts = append(parts, e.Code+": "+e.Message)
	}
	if len(parts) == 0 {
		return result.Action + " failed"
	}
	return result.Action + " failed: " + joinMessages(parts)
}

func runEnterpriseSecret(cmd *cobra.Command, action string, opts *enterpriseSecretOptions) error {
	goos := enterpriseunix.CurrentGOOS()
	env, err := newUnixLifecycleEnv(goos)
	if err != nil {
		return withExitCode(err, enterprisestatus.UnixExitFailure)
	}
	if action != "status" && env.Geteuid() != 0 {
		return withExitCode(errors.New("run this command as root"), enterprisestatus.UnixExitFailure)
	}
	switch action {
	case "status":
		states, err := env.SecretStatus()
		if err != nil {
			return withExitCode(err, enterprisestatus.UnixExitFailure)
		}
		if opts.json {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]any{"schema_version": 1, "secrets": states})
		}
		if len(states) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "no protected credentials")
		}
		for _, state := range states {
			fmt.Fprintf(cmd.OutOrStdout(), "%-32s sha256:%s… mode %s modified %s\n", state.Name, state.SHA256Prefix, state.Mode, state.ModifiedAt)
		}
		return nil
	case "set":
		if opts.fromStdin == (opts.fromFile != "") {
			return withExitCode(errors.New("pass exactly one of --from-stdin or --from-file"), enterprisestatus.UnixExitInvalidArgs)
		}
		var source io.Reader = cmd.InOrStdin()
		if opts.fromFile != "" {
			file, err := os.Open(opts.fromFile)
			if err != nil {
				return withExitCode(err, enterprisestatus.UnixExitFailure)
			}
			defer file.Close()
			source = file
		}
		value, err := enterpriseunix.ReadSecretValue(source)
		if err != nil {
			return withExitCode(err, enterprisestatus.UnixExitInvalidArgs)
		}
		if err := env.WriteSecret(cmd.Context(), opts.name, value); err != nil {
			return withExitCode(err, enterprisestatus.UnixExitFailure)
		}
	case "remove":
		if err := env.RemoveSecret(opts.name); err != nil {
			return withExitCode(err, enterprisestatus.UnixExitFailure)
		}
	}
	// Apply the change now; the apply path unit would also pick it up.
	result := enterpriseunix.Run(cmd.Context(), env, enterpriseunix.Options{Action: enterpriseunix.ActionEnsure, Reason: "secret"})
	if err := printLifecycleResult(cmd.OutOrStdout(), result, opts.json); err != nil {
		return err
	}
	if !result.OK {
		return withExitCode(errors.New(lifecycleErrorSummary(result)), result.ExitCode)
	}
	return nil
}
