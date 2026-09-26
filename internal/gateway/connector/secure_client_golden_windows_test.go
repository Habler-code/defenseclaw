// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// Secure Client golden: the Claude Code managed-settings drop-in that
// production Windows Secure Client installs publish as
// C:\Program Files\ClaudeCode\managed-settings.d\90-defenseclaw.json.
// See testdata/secure_client_golden/README.md.
func TestSecureClientGoldenClaudeManagedPolicy(t *testing.T) {
	for _, version := range []string{"2.1.154", "2.1.207"} {
		t.Run(version, func(t *testing.T) {
			opts := SetupOpts{
				ManagedEnterprise: true,
				DataDir:           `C:\Users\alice\.defenseclaw`,
				APIAddr:           "127.0.0.1:18970",
				HookExecutable:    `C:\Program Files\Cisco\Cisco Secure Client\DefenseClaw\bin\defenseclaw-hook.exe`,
				AgentVersion:      version,
			}
			c := NewClaudeCodeConnector()
			body, err := c.ManagedHookPolicy(opts)
			if err != nil {
				t.Fatalf("ManagedHookPolicy: %v", err)
			}
			if err := c.VerifyManagedHookPolicy(body, opts); err != nil {
				t.Fatalf("VerifyManagedHookPolicy: %v", err)
			}
			testenv.CompareSecureClientGoldenBytes(t, "windows/claude_managed_policy_"+version+".json", body)
		})
	}
}
