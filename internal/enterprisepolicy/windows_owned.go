// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"fmt"
)

// windowsGoOwnedTargets are the machine policy targets the Go guardian owns
// on the Windows standalone profile. The Windows lifecycle already owns the
// Codex requirements, the Claude Code managed settings and the Cursor
// enterprise hooks, with their own ownership records and transactions; a
// second writer would race them, so the guardian never reconciles those.
var windowsGoOwnedTargets = map[string]bool{
	ConnectorCopilot:  true,
	ConnectorOpenCode: true,
}

// IsWindowsGoOwned reports whether the Go guardian owns connector's Windows
// machine policy.
func IsWindowsGoOwned(connector string) bool {
	return windowsGoOwnedTargets[connector]
}

// PublishWindowsGoOwned reconciles only the Go-owned Windows machine policy
// targets among connectors and writes the public summary for every
// connector, so the hook-side foreign-hook guard sees the whole policy.
func PublishWindowsGoOwned(opts Options, connectors []string) (Result, error) {
	if err := opts.Validate(); err != nil {
		return Result{}, err
	}
	if opts.goos() != "windows" {
		return Result{}, errors.New("PublishWindowsGoOwned applies only to Windows")
	}
	connectors = normalizeConnectors(connectors)
	result := Result{}
	var errs []error
	for _, name := range connectors {
		if !windowsGoOwnedTargets[name] {
			continue
		}
		state, err := reconcileOne(opts, name)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
		result.Changed = result.Changed || state.Changed
		result.States = append(result.States, state)
	}
	result.MachinePolicyConnectors = reconciledConnectors(result.States)
	intended := []string{}
	for _, name := range MachinePolicyConnectors(opts, connectors) {
		if windowsGoOwnedTargets[name] {
			intended = append(intended, name)
		}
	}
	retired, err := retireUnpublished(opts, intended, []string{ConnectorCopilot, ConnectorOpenCode})
	if err != nil {
		errs = append(errs, err)
	}
	result.Retired = retired
	for _, state := range retired {
		result.Changed = result.Changed || state.Changed
	}
	if opts.PublicPolicyPath != "" {
		changed, err := WritePublicPolicy(opts, connectors)
		if err != nil {
			errs = append(errs, fmt.Errorf("public machine policy summary: %w", err))
		}
		result.Changed = result.Changed || changed
	}
	return result, errors.Join(errs...)
}

// RemoveWindowsGoOwned removes the DefenseClaw entries of the Go-owned
// Windows targets and the public summary. Administrator files are left
// byte-identical.
func RemoveWindowsGoOwned(opts Options) (Result, error) {
	if opts.goos() != "windows" {
		return Result{}, errors.New("RemoveWindowsGoOwned applies only to Windows")
	}
	result := Result{}
	var errs []error
	for _, name := range []string{ConnectorCopilot, ConnectorOpenCode} {
		target, ok := TargetFor(name)
		if !ok {
			continue
		}
		state, err := target.RemoveOwned(opts)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
		result.Changed = result.Changed || state.Changed
		result.States = append(result.States, state)
	}
	if opts.PublicPolicyPath != "" {
		if err := removePolicyFile(opts, opts.PublicPolicyPath); err != nil {
			errs = append(errs, err)
		}
	}
	return result, errors.Join(errs...)
}
