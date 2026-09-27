// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// Setup writes `hook --connector kiro --hook-surface v3` into the
// .kiro/hooks config on Windows. The hook must parse it: an unknown flag is a
// usage error, which exits 1, and Kiro proceeds past any status other than 0
// and 2, so every Kiro IDE and kiro-cli --v3 event used to go through with a
// warning.
func TestHookAcceptsKiroHookSurface(t *testing.T) {
	cmd := newHookCmd()
	if err := cmd.ParseFlags([]string{"--connector", "kiro", "--hook-surface", "v3"}); err != nil {
		t.Fatalf("parse the Kiro v3 hook command: %v", err)
	}
	flag := cmd.Flags().Lookup("hook-surface")
	if flag == nil || !flag.Hidden {
		t.Fatalf("hook-surface must be a hidden machine-facing flag, got %+v", flag)
	}
}

// A Kiro hook that fails before it can run (a flag it does not know, a value
// it does not list, a stray argument) must exit 2 so Kiro blocks instead of
// going ahead, when its policy is to fail closed: an administrator-managed
// hook, or fail mode closed from --fail-mode, the hook sidecar or
// DEFENSECLAW_FAIL_MODE. A fail-open Kiro hook and every other connector
// keep cobra's status 1 (decision D6 approved the --hook-surface fix, not a
// change of the fail-open policy).
func TestHookPreRunFailureUsesTheConnectorsBlockingExit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		args    []string
		sidecar string
		env     string
		want    int
	}{
		{name: "kiro fail closed, unknown flag", args: []string{"--connector", "kiro", "--not-a-hook-flag", "--fail-mode", "closed"}, want: 2},
		{name: "kiro fail closed, unlisted surface", args: []string{"--connector", "kiro", "--fail-mode=closed", "--hook-surface", "v9"}, want: 2},
		{name: "kiro fail closed, positional argument", args: []string{"--connector", "kiro", "--fail-mode", "closed", "stray"}, want: 2},
		{name: "kiro managed, connector spelled with =", args: []string{"--connector=kiro", "--not-a-hook-flag", "--enterprise-managed"}, want: 2},
		{name: "kiro closed in the hook sidecar", args: []string{"--connector", "kiro", "--not-a-hook-flag"}, sidecar: `{"version":2,"fail_modes":{"kiro":"closed"}}`, want: 2},
		{name: "kiro closed in the environment", args: []string{"--connector", "kiro", "--not-a-hook-flag"}, env: "closed", want: 2},
		{name: "kiro fail open keeps 1", args: []string{"--connector", "kiro", "--not-a-hook-flag"}, want: 1},
		{name: "kiro open in the sidecar keeps 1", args: []string{"--connector", "kiro", "--hook-surface", "v9"}, sidecar: `{"version":2,"fail_modes":{"kiro":"open"}}`, want: 1},
		{name: "codex unknown flag", args: []string{"--connector", "codex", "--not-a-hook-flag", "--fail-mode", "closed"}, want: 1},
		{name: "surface on a connector that lists none", args: []string{"--connector", "codex", "--hook-surface", "v3"}, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", home)
			t.Setenv("DEFENSECLAW_FAIL_MODE", tc.env)
			if tc.sidecar != "" {
				if err := os.MkdirAll(filepath.Join(home, "hooks"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(home, "hooks", ".hookcfg"), []byte(tc.sidecar), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			previous := hookRawArgs
			hookRawArgs = func() []string { return tc.args }
			t.Cleanup(func() { hookRawArgs = previous })
			cmd := newHookCmd()
			cmd.SetArgs(tc.args)
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			err := cmd.Execute()
			if err == nil {
				t.Fatalf("hook %v succeeded, want a usage failure", tc.args)
			}
			if got := commandExitCode(err); got != tc.want {
				t.Fatalf("hook %v exit = %d, want %d (err=%v)", tc.args, got, tc.want, err)
			}
		})
	}
}
