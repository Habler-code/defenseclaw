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
// going ahead. Other connectors keep cobra's status 1.
func TestHookPreRunFailureUsesTheConnectorsBlockingExit(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{name: "kiro unknown flag", args: []string{"--connector", "kiro", "--not-a-hook-flag"}, want: 2},
		{name: "kiro unlisted surface", args: []string{"--connector", "kiro", "--hook-surface", "v9"}, want: 2},
		{name: "kiro positional argument", args: []string{"--connector", "kiro", "stray"}, want: 2},
		{name: "kiro connector spelled with =", args: []string{"--connector=kiro", "--not-a-hook-flag"}, want: 2},
		{name: "codex unknown flag", args: []string{"--connector", "codex", "--not-a-hook-flag"}, want: 1},
		{name: "surface on a connector that lists none", args: []string{"--connector", "codex", "--hook-surface", "v3"}, want: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
