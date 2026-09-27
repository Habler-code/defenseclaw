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

package enterpriseunix

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// observingRunner calls observe before every command it passes on.
type observingRunner struct {
	Runner
	observe func(name string, args []string)
}

func (r observingRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	r.observe(name, args)
	return r.Runner.Run(ctx, name, args...)
}

// observingPolicy calls observe before removing machine policy.
type observingPolicy struct {
	MachinePolicyManager
	observe func()
}

func (p observingPolicy) RemoveAll() (enterprisepolicy.Result, error) {
	p.observe()
	return p.MachinePolicyManager.RemoveAll()
}

// The guardian repairs any DefenseClaw registration that disappears from a
// manifest target within about a second. Uninstall must stop it, the
// enumerator and the lifecycle triggers before it removes the per-user and
// machine-policy registrations, or the guardian puts them back and they
// outlive the binary they name. The gateway keeps answering until then.
func TestUninstallStopsRepairersBeforeRemovingRegistrations(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			gateway := unitGateway
			if goos == "darwin" {
				gateway = labelGateway
			}
			var problems []string
			check := func(step string) {
				for _, unit := range h.services.Units() {
					if repairsRegistrations(unit) && h.services.isActive(unit.Name) {
						problems = append(problems, step+": "+unit.Name+" still running")
					}
				}
				if !h.services.isActive(gateway) {
					problems = append(problems, step+": the gateway was already stopped")
				}
			}
			removeAll := false
			h.env.Runner = observingRunner{Runner: h.runner, observe: func(name string, args []string) {
				if strings.Contains(strings.Join(args, " "), "hooks remove-all") {
					removeAll = true
					check("per-user remove-all")
				}
			}}
			policyRemoved := false
			h.env.MachinePolicy = observingPolicy{MachinePolicyManager: h.env.MachinePolicy, observe: func() {
				policyRemoved = true
				check("machine policy removal")
			}}
			requireOK(t, h.run(Options{Action: ActionUninstall}))
			if !removeAll || !policyRemoved {
				t.Fatalf("uninstall skipped a registration removal: per-user=%v machine-policy=%v", removeAll, policyRemoved)
			}
			if len(problems) > 0 {
				t.Fatalf("registrations were removed while they could be repaired:\n%s", strings.Join(problems, "\n"))
			}
			for _, unit := range h.services.Units() {
				if h.services.isActive(unit.Name) {
					t.Fatalf("%s still running after uninstall", unit.Name)
				}
				if unit.Activate && h.services.enabled[unit.Name] {
					t.Fatalf("%s still enabled after uninstall", unit.Name)
				}
			}
		})
	}
}
