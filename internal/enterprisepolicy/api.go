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
	"sort"
	"strings"
)

// Result is the aggregate lifecycle outcome.
type Result struct {
	States []State `json:"states"`
	// MachinePolicyConnectors lists the machine-policy connectors whose
	// DefenseClaw entries are actually in place after this pass; the
	// lifecycle records exactly this set in the runtime descriptor.
	MachinePolicyConnectors []string `json:"machine_policy_connectors"`
	Changed                 bool     `json:"changed"`
}

// Complete reports whether every machine-policy connector is covered.
func (r Result) Complete() bool {
	for _, state := range r.States {
		if state.Route == RouteMachinePolicy && !state.Covered {
			return false
		}
	}
	return true
}

func normalizeConnectors(connectors []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, name := range connectors {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Publish reconciles machine policy for every enabled connector that has a
// machine policy route and writes the public foreign-hook guard summary.
// Connectors on other routes are reported with their route so status shows
// every connector.
func Publish(opts Options, connectors []string) (Result, error) {
	if err := opts.Validate(); err != nil {
		return Result{}, err
	}
	connectors = normalizeConnectors(connectors)
	result := Result{}
	var errs []error
	for _, name := range connectors {
		state, err := reconcileOne(opts, name)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
		result.Changed = result.Changed || state.Changed
		result.States = append(result.States, state)
	}
	result.MachinePolicyConnectors = reconciledConnectors(result.States)
	if opts.PublicPolicyPath != "" {
		changed, err := WritePublicPolicy(opts, connectors)
		if err != nil {
			errs = append(errs, fmt.Errorf("public machine policy summary: %w", err))
		}
		result.Changed = result.Changed || changed
	}
	return result, errors.Join(errs...)
}

func reconcileOne(opts Options, name string) (State, error) {
	route := opts.Route(name)
	policy := opts.PolicyFor(name)
	if route != RouteMachinePolicy {
		state := State{Connector: name, Route: route, ForeignHooks: policy.ForeignHooks}
		if route == RoutePerUser {
			state.detail("per-user registration of the admin hook binary, repaired by the guardian")
		}
		return state, nil
	}
	target, _ := TargetFor(name)
	return target.Reconcile(opts)
}

// VerifyAll inspects every connector without writing.
func VerifyAll(opts Options, connectors []string) (Result, error) {
	if err := opts.Validate(); err != nil {
		return Result{}, err
	}
	connectors = normalizeConnectors(connectors)
	result := Result{}
	var errs []error
	for _, name := range connectors {
		route := opts.Route(name)
		if route != RouteMachinePolicy {
			result.States = append(result.States, State{Connector: name, Route: route, ForeignHooks: opts.PolicyFor(name).ForeignHooks})
			continue
		}
		target, _ := TargetFor(name)
		state, err := target.Verify(opts)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
		result.States = append(result.States, state)
	}
	result.MachinePolicyConnectors = reconciledConnectors(result.States)
	return result, errors.Join(errs...)
}

// RemoveAll removes DefenseClaw's machine policy for every connector with a
// machine policy target (whether or not it is still enabled) and deletes
// the public summary.
func RemoveAll(opts Options) (Result, error) {
	names := make([]string, 0, len(targets))
	for name := range targets {
		names = append(names, name)
	}
	sort.Strings(names)
	result := Result{}
	var errs []error
	for _, name := range names {
		state, err := targets[name].RemoveOwned(opts)
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
