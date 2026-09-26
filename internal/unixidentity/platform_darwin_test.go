//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package unixidentity

import (
	"context"
	"fmt"
	"os"
	"os/user"
	"testing"
)

func TestParseDSCLUniqueIDsResolvesAndSkipsDaemonAccounts(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	output := fmt.Sprintf("_spotlight 89\n%s %s\nbogus notanumber\nghost 4000000123\n", current.Username, current.Uid)
	accounts := parseDSCLUniqueIDs(output, NewOSUserResolver(context.Background()))
	if len(accounts) != 1 || accounts[0].Name != current.Username {
		t.Fatalf("parseDSCLUniqueIDs = %+v", accounts)
	}
	if accounts[0].UID != os.Getuid() {
		t.Fatalf("uid = %d, want %d", accounts[0].UID, os.Getuid())
	}
}

func TestDarwinDefaultResolverFindsCurrentUser(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Skip(err)
	}
	account, err := Default(context.Background()).LookupUser(current.Username)
	if err != nil || account.Home != current.HomeDir {
		t.Fatalf("LookupUser(%s) = %+v, %v", current.Username, account, err)
	}
	if _, err := Default(context.Background()).LookupUser("dc-no-such-user-7f3a"); !IsNotFound(err) {
		t.Fatalf("missing account error = %v, want ErrNotFound", err)
	}
}
