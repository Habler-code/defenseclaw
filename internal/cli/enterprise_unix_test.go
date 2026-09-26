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

import "testing"

func TestUnixEnterpriseCommandTree(t *testing.T) {
	for _, group := range []string{"linux", "macos"} {
		for _, action := range []string{"install", "upgrade", "repair", "ensure", "reconcile", "status", "verify", "uninstall"} {
			cmd, _, err := rootCmd.Find([]string{"enterprise", group, action})
			if err != nil || cmd == nil || cmd.Name() != action {
				t.Fatalf("enterprise %s %s not registered: %v", group, action, err)
			}
			if cmd.Flags().Lookup("json") == nil {
				t.Fatalf("enterprise %s %s has no --json", group, action)
			}
		}
		ensure, _, _ := rootCmd.Find([]string{"enterprise", group, "ensure"})
		for _, flag := range []string{"payload", "from-package", "config", "no-start", "adopt-existing", "product-version", "reason"} {
			if ensure.Flags().Lookup(flag) == nil {
				t.Fatalf("enterprise %s ensure lacks --%s", group, flag)
			}
		}
		uninstall, _, _ := rootCmd.Find([]string{"enterprise", group, "uninstall"})
		if uninstall.Flags().Lookup("purge") == nil || uninstall.Flags().Lookup("payload") != nil {
			t.Fatalf("enterprise %s uninstall flags are wrong", group)
		}
	}
	for _, action := range []string{"set", "status", "remove"} {
		if cmd, _, err := rootCmd.Find([]string{"enterprise", "secret", action}); err != nil || cmd.Name() != action {
			t.Fatalf("enterprise secret %s not registered: %v", action, err)
		}
	}
	set, _, _ := rootCmd.Find([]string{"enterprise", "secret", "set"})
	if set.Flags().Lookup("from-stdin") == nil || set.Flags().Lookup("name") == nil {
		t.Fatal("enterprise secret set lacks --name/--from-stdin")
	}
}
