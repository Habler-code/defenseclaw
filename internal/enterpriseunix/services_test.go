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
	"reflect"
	"sort"
	"testing"

	launchdstandalone "github.com/defenseclaw/defenseclaw/packaging/launchd-standalone"
	systemdunits "github.com/defenseclaw/defenseclaw/packaging/systemd"
)

// The lifecycle manages exactly the reviewed unit files that ship in the
// repository and packages: a unit added to one side only would either never
// be installed or never be stopped.
func TestManagedUnitsMatchEmbeddedDefinitions(t *testing.T) {
	names := func(units []Unit) []string {
		out := make([]string, 0, len(units))
		for _, unit := range units {
			out = append(out, unit.Name)
		}
		sort.Strings(out)
		return out
	}
	if got, want := names(linuxUnits), systemdunits.Units(); !reflect.DeepEqual(got, want) {
		t.Fatalf("linux units %v, embedded %v", got, want)
	}
	if got, want := names(darwinUnits), launchdstandalone.Labels(); !reflect.DeepEqual(got, want) {
		t.Fatalf("darwin units %v, embedded %v", got, want)
	}
}

// Activation order: sensor helper, then the gateway sockets and gateway,
// then the guardian and enumerator.
func TestActivationStagesFollowDependencies(t *testing.T) {
	stage := map[string]int{}
	for _, unit := range linuxUnits {
		stage[unit.Name] = unit.Stage
	}
	order := []string{unitSensorHelper, unitGateway, unitGuardian, unitEnumerator}
	for i := 1; i < len(order); i++ {
		if stage[order[i-1]] >= stage[order[i]] {
			t.Fatalf("%s (stage %d) must activate before %s (stage %d)", order[i-1], stage[order[i-1]], order[i], stage[order[i]])
		}
	}
}
