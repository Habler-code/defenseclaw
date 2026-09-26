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

package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// standaloneEnterprisePolicyLayout returns the standalone layout and, on
// Windows only, the trusted machine roots.
func standaloneEnterprisePolicyLayout() (managed.StandaloneLayout, string, string, error) {
	layout, err := managed.StandaloneLayoutFor(runtime.GOOS)
	return layout, "", "", err
}

// enterprisePolicyTarget resolves a local account for per-user checks.
func enterprisePolicyTarget(name string) (enterprisehooks.TargetCredentials, error) {
	account, err := user.Lookup(name)
	if err != nil {
		return enterprisehooks.TargetCredentials{}, fmt.Errorf("look up user %q: %w", name, err)
	}
	uid, uidErr := strconv.Atoi(account.Uid)
	gid, gidErr := strconv.Atoi(account.Gid)
	if uidErr != nil || gidErr != nil {
		return enterprisehooks.TargetCredentials{}, fmt.Errorf("user %q has a non-numeric uid/gid", name)
	}
	return enterprisehooks.TargetCredentials{UserHome: account.HomeDir, UID: uid, GID: gid}, nil
}

// runAsEnterprisePolicyTarget reads the user's files with the user's own
// credentials when running as root, so a crafted symlink in a home cannot
// make the administrator read files the user could not.
func runAsEnterprisePolicyTarget(target enterprisehooks.TargetCredentials, fn func() error) error {
	if os.Geteuid() != 0 {
		if target.UID != os.Geteuid() {
			return errors.New("run as root or as the target user")
		}
		return fn()
	}
	return enterprisehooks.RunAsTarget(target, fn)
}

// enterprisePolicyLiveCredential starts the agent as the target user.
func enterprisePolicyLiveCredential(target enterprisehooks.TargetCredentials) func(*exec.Cmd) error {
	return func(cmd *exec.Cmd) error {
		if os.Geteuid() != 0 {
			if target.UID != os.Geteuid() {
				return errors.New("live verification must run as root or as the target user")
			}
			return nil
		}
		groups := []uint32{}
		if account, err := user.LookupId(strconv.Itoa(target.UID)); err == nil {
			if ids, err := account.GroupIds(); err == nil {
				for _, id := range ids {
					if value, err := strconv.ParseUint(id, 10, 32); err == nil {
						groups = append(groups, uint32(value))
					}
				}
			}
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{
			Uid:    uint32(target.UID),
			Gid:    uint32(target.GID),
			Groups: groups,
		}}
		return nil
	}
}

// hookForeignGuardHomes lists the homes an agent may read hook config
// from: the account's passwd home and, when different, $HOME as inherited
// from the agent. Replaceable in tests.
var hookForeignGuardHomes = func() []string {
	homes := []string{}
	if account, err := user.LookupId(strconv.Itoa(os.Getuid())); err == nil && account.HomeDir != "" {
		homes = append(homes, account.HomeDir)
	}
	return appendDistinctAbs(homes, os.Getenv("HOME"))
}
