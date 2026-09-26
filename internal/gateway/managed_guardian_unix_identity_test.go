//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The standalone Unix guardian records each protected target's uid and
// home inode; the gateway's strict ledger decode must accept them.
func TestManagedGuardianCoverageAcceptsStandaloneUnixIdentity(t *testing.T) {
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, t.TempDir())
	oldValidate := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(_, _ string) error { return nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization = oldValidate })
	path := managed.HookGuardianAuthorizationPath(t.TempDir())
	data := []byte(fmt.Sprintf(`{
		"version":1,
		"updated_at":%q,
		"ok":true,
		"target_count":1,
		"success_count":1,
		"failure_count":0,
		"protected_targets":[{"user":"ldapuser","user_home":"/home/ldapuser","connector":"codex","ok":true,"uid":1234567,"home_inode":42}]
	}`, time.Now().UTC().Format(time.RFC3339)))
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if ok, reason := managedGuardianCoversConnectors("unused", []string{"codex"}); !ok {
		t.Fatalf("a standalone ledger row with uid and home_inode was rejected: %s", reason)
	}
}

// A directory (NSS/SSSD/LDAP) user is invisible to a cgo-free build's
// os/user, so the hook socket sees only the kernel uid. The guardian's
// numeric uid lets that user match; a row without a uid (an older guardian)
// still matches by name, and a uid row never matches a different uid that
// reuses the name.
func TestManagedHookAuthorizerMatchesNSSOnlyUserByLedgerUID(t *testing.T) {
	t.Setenv(managed.HookGuardianAuthorizationDirEnv, t.TempDir())
	oldValidate := validateManagedGuardianAuthorization
	validateManagedGuardianAuthorization = func(_, _ string) error { return nil }
	t.Cleanup(func() { validateManagedGuardianAuthorization = oldValidate })
	path := managed.HookGuardianAuthorizationPath(t.TempDir())
	data := []byte(`{"version":1,"updated_at":"2026-09-26T00:00:00Z","ok":true,"target_count":2,"success_count":2,"failure_count":0,"protected_targets":[
		{"user":"ldapuser","user_home":"/home/ldapuser","connector":"codex","ok":true,"uid":1234567,"home_inode":42},
		{"user":"legacy","user_home":"/home/legacy","connector":"codex","ok":true}
	]}`)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	authorizer := newManagedHookAuthorizer(config.EnterpriseEnrollmentConfig{}, nil, func() (managedHookLedger, error) {
		return readManagedHookLedger(path)
	})
	for _, tc := range []struct {
		name  string
		peer  managedHookPeer
		allow bool
	}{
		{"nss-only user by uid", managedHookPeer{UID: 1234567}, true},
		{"nss-only user on another connector", managedHookPeer{UID: 1234567}, false},
		{"uid row ignores a name reused by another uid", managedHookPeer{UID: 7654321, Name: "ldapuser"}, false},
		{"legacy row by name", managedHookPeer{UID: 2001, Name: "legacy"}, true},
		{"legacy row without a resolvable name", managedHookPeer{UID: 2001}, false},
	} {
		connectorName := "codex"
		if tc.name == "nss-only user on another connector" {
			connectorName = "claudecode"
		}
		if got := authorizer.decide(tc.peer, connectorName); got.Allow != tc.allow {
			t.Errorf("%s: allow = %v (%s), want %v", tc.name, got.Allow, got.Reason, tc.allow)
		}
	}
}
