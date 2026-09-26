// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// Standalone per-user connectors (Copilot, Antigravity, Devin, Hermes,
// OpenCode, Amp) are part of the managed-hook teardown only in a process
// pinned to the standalone profile. Their machine wiring is the per-user
// enrollment and runtime selector of each hook-binary connector, plus the
// Go-owned Copilot machine policy and public summary. Per-user runtime files
// stay, like every other connector.

func windowsManagedHooksStandalonePerUserTarget(connectorName string) bool {
	_, perUser := enterprisehooks.IsWindowsStandalonePerUserConnector(connectorName)
	return perUser && enterprisehooks.WindowsStandaloneProcess()
}

// windowsManagedHooksStandalonePerUserExpected is the enrollment an
// activated deployment carries: every activated, non-pending target of each
// hook-binary per-user connector.
func windowsManagedHooksStandalonePerUserExpected(
	identity windowsManagedHooksTeardownJournal,
) map[string][]enterprisehooks.WindowsPerUserManagedEnrollmentTarget {
	expected := map[string][]enterprisehooks.WindowsPerUserManagedEnrollmentTarget{}
	for _, target := range identity.Targets {
		hookBinary, perUser := enterprisehooks.IsWindowsStandalonePerUserConnector(target.Connector)
		if !perUser || !hookBinary {
			continue
		}
		expected[target.Connector] = expected[target.Connector]
		if !windowsManagedHooksTeardownSelectorExpected(target, identity.PendingTargets, identity.ActivationState) {
			continue
		}
		expected[target.Connector] = append(expected[target.Connector],
			enterprisehooks.WindowsPerUserManagedEnrollmentTarget{SID: target.SID, DataDir: target.DataDir})
	}
	return expected
}

func windowsManagedHooksStandalonePerUserConnectors(targets []windowsManagedHooksTeardownTarget) []string {
	seen := map[string]bool{}
	names := []string{}
	for _, target := range targets {
		if _, perUser := enterprisehooks.IsWindowsStandalonePerUserConnector(target.Connector); perUser && !seen[target.Connector] {
			seen[target.Connector] = true
			names = append(names, target.Connector)
		}
	}
	sort.Strings(names)
	return names
}

func validateWindowsManagedHooksStandalonePerUserEnrollment(identity windowsManagedHooksTeardownJournal) error {
	for connectorName, want := range windowsManagedHooksStandalonePerUserExpected(identity) {
		current, exists, err := enterprisehooks.ReadWindowsPerUserManagedEnrollmentTargets(connectorName)
		if err != nil {
			return err
		}
		if exists != (len(want) != 0) || !equalWindowsPerUserEnrollmentTargets(current, want) {
			return fmt.Errorf("%s machine enrollment does not match the authenticated activation state", connectorName)
		}
	}
	return nil
}

func equalWindowsPerUserEnrollmentTargets(left, right []enterprisehooks.WindowsPerUserManagedEnrollmentTarget) bool {
	if len(left) != len(right) {
		return false
	}
	index := map[string]string{}
	for _, target := range left {
		index[strings.ToUpper(target.SID)] = target.DataDir
	}
	for _, target := range right {
		dataDir, ok := index[strings.ToUpper(target.SID)]
		if !ok || !sameWindowsEnterprisePathCLI(dataDir, target.DataDir) {
			return false
		}
	}
	return true
}

func removeWindowsManagedHooksStandalonePerUserWiring(identity windowsManagedHooksTeardownJournal) error {
	if !enterprisehooks.WindowsStandaloneProcess() {
		return nil
	}
	// Revoke every per-user enrollment, not only the manifest connectors, so
	// an uninstall leaves no enrolled SID behind.
	if err := enterprisehooks.RemoveWindowsPerUserManagedEnrollments(
		identity.HookBinary,
		enterprisehooks.WindowsStandalonePerUserConnectorNames(),
	); err != nil {
		return err
	}
	layout, programFiles, programData, err := standaloneEnterprisePolicyLayout()
	if err != nil {
		return err
	}
	_, err = enterprisepolicy.RemoveWindowsGoOwned(enterprisepolicy.LayoutOptions(layout, programFiles, programData))
	return err
}

func restoreWindowsManagedHooksStandalonePerUserEnrollments(journal windowsManagedHooksTeardownJournal) error {
	var errs []error
	for connectorName, targets := range windowsManagedHooksStandalonePerUserExpected(journal) {
		if len(targets) == 0 {
			continue
		}
		if err := enterprisehooks.RestoreWindowsPerUserManagedEnrollment(connectorName, journal.HookBinary, targets); err != nil {
			errs = append(errs, err)
		}
	}
	// The Go-owned Copilot policy and summary are republished by the
	// guardian's next reconcile once the rolled-back services start.
	return errors.Join(errs...)
}

func verifyWindowsManagedHooksStandalonePerUserClean(targets []windowsManagedHooksTeardownTarget) error {
	connectors := windowsManagedHooksStandalonePerUserConnectors(targets)
	if enterprisehooks.WindowsStandaloneProcess() {
		connectors = enterprisehooks.WindowsStandalonePerUserConnectorNames()
	}
	for _, connectorName := range connectors {
		_, exists, err := enterprisehooks.ReadWindowsPerUserManagedEnrollmentTargets(connectorName)
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("%s machine enrollment survived managed-hook teardown", connectorName)
		}
	}
	return nil
}
