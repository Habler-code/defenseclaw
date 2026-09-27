// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func perUserTeardownManifest(connectorName string) enterprisehooks.Manifest {
	return enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{{
		Connector:    connectorName,
		UserHome:     `C:\Users\dcw-std1`,
		SID:          "S-1-5-21-1000000000-2000000000-3000000000-1017",
		AgentVersion: "1.0.88",
	}}}
}

func TestWindowsManagedHooksTeardownTargetsAcceptPerUserOnlyInStandalone(t *testing.T) {
	t.Setenv(managed.EnterpriseProfileEnv, "")
	if _, _, _, _, err := windowsManagedHooksTeardownTargets(perUserTeardownManifest("copilot")); err == nil ||
		!strings.Contains(err.Error(), "does not support connector") {
		t.Fatalf("Secure Client teardown accepted copilot: %v", err)
	}
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	for _, name := range []string{"copilot", "devin", "amp"} {
		targets, claude, codex, cursor, err := windowsManagedHooksTeardownTargets(perUserTeardownManifest(name))
		if err != nil || len(targets) != 1 || len(claude)+len(codex)+len(cursor) != 0 {
			t.Fatalf("%s: targets=%v err=%v", name, targets, err)
		}
	}
	if _, _, _, _, err := windowsManagedHooksTeardownTargets(perUserTeardownManifest("openhands")); err == nil {
		t.Fatal("standalone teardown accepted openhands")
	}
}

func TestWindowsManagedHooksTeardownPluginConnectorsHaveNoSelector(t *testing.T) {
	t.Setenv(managed.EnterpriseProfileEnv, managed.ProfileStandalone)
	for name, want := range map[string]bool{"copilot": true, "devin": true, "amp": false, "opencode": true, "codex": true} {
		target := windowsManagedHooksTeardownTarget{Connector: name, SID: "S-1-5-21-1-2-3-1017", DataDir: `C:\Users\u\.defenseclaw`}
		if got := windowsManagedHooksTeardownSelectorExpected(target, nil, windowsManagedHooksActivated); got != want {
			t.Fatalf("%s selector expected = %t, want %t", name, got, want)
		}
	}
	identity := windowsManagedHooksTeardownJournal{
		ActivationState: windowsManagedHooksActivated,
		Targets: []windowsManagedHooksTeardownTarget{
			{Connector: "devin", SID: "S-1-5-21-1-2-3-1017", DataDir: `C:\Users\a\.defenseclaw`},
			{Connector: "devin", SID: "S-1-5-21-1-2-3-1018", DataDir: `C:\Users\b\.defenseclaw`},
			{Connector: "amp", SID: "S-1-5-21-1-2-3-1017", DataDir: `C:\Users\a\.defenseclaw`},
		},
		PendingTargets: []windowsManagedHooksTeardownTarget{
			{Connector: "devin", SID: "S-1-5-21-1-2-3-1018", DataDir: `C:\Users\b\.defenseclaw`},
		},
	}
	expected := windowsManagedHooksStandalonePerUserExpected(identity)
	if len(expected) != 1 || len(expected["devin"]) != 1 || expected["devin"][0].SID != "S-1-5-21-1-2-3-1017" {
		t.Fatalf("expected per-user enrollment = %+v", expected)
	}
	identity.ActivationState = windowsManagedHooksNeverActivated
	if got := windowsManagedHooksStandalonePerUserExpected(identity)["devin"]; len(got) != 0 {
		t.Fatalf("never-activated deployment expects enrollment %+v", got)
	}
}

func TestWindowsStandalonePerUserEnrollmentKeepFollowsManifest(t *testing.T) {
	manifest := enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{
		{Connector: "devin", SID: "S-1-5-21-1-2-3-1017"},
		{Connector: "hermes", SID: "S-1-5-21-1-2-3-1018", Enabled: boolPointerForTest(false)},
	}}
	keep := windowsStandalonePerUserEnrollmentKeep(manifest)
	if !keep("devin", "s-1-5-21-1-2-3-1017") {
		t.Fatal("enabled row not kept")
	}
	if keep("hermes", "S-1-5-21-1-2-3-1018") || keep("devin", "S-1-5-21-1-2-3-1018") || keep("copilot", "S-1-5-21-1-2-3-1017") {
		t.Fatal("unauthorized SID kept")
	}
}

func boolPointerForTest(value bool) *bool { return &value }
