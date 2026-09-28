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

package actionfacts

import (
	"reflect"
	"testing"
)

func TestDynamicRedirectTargetReduction(t *testing.T) {
	tests := []struct {
		name    string
		command string
		reduced bool
		// kept is the number of static redirects left on the first command.
		kept int
	}{
		{name: "tilde target", command: "echo dccert-block-marker > ~/dccert-x.txt", reduced: true},
		{name: "HOME target", command: "echo dccert-block-marker > $HOME/dccert-x.txt", reduced: true},
		{name: "quoted HOME append", command: `echo dccert-block-marker >> "$HOME/dccert-x.txt"`, reduced: true},
		{name: "glob target", command: "echo dccert-block-marker > dccert-*.txt", reduced: true},
		{name: "static stderr kept", command: "echo dccert-block-marker 2>/dev/null > ~/dccert-x.txt", reduced: true, kept: 1},
		{name: "pipeline", command: "echo dccert-block-marker | cat > ~/dccert-x.txt", reduced: true},

		{name: "complete action", command: "echo dccert-block-marker > /tmp/dccert-x.txt"},
		{name: "expanding argument", command: "echo $MARKER > /tmp/dccert-x.txt"},
		{name: "expanding argument and target", command: "echo dccert-block-marker $SUFFIX > ~/dccert-x.txt"},
		{name: "expanding program", command: "$ECHO dccert-block-marker > ~/dccert-x.txt"},
		{name: "chained with and", command: "cd /tmp && echo dccert-block-marker > ~/dccert-x.txt"},
		{name: "chained with or", command: "echo dccert-block-marker > ~/dccert-x.txt || true"},
		{name: "background", command: "echo dccert-block-marker > ~/dccert-x.txt &"},
		{name: "negated", command: "! echo dccert-block-marker > ~/dccert-x.txt"},
		{name: "descriptor copy", command: "echo dccert-block-marker 2>&1 > ~/dccert-x.txt"},
		{name: "prefix assignment", command: "MARKER=1 echo dccert-block-marker > ~/dccert-x.txt"},
		{name: "command substitution", command: "echo $(id -un) > ~/dccert-x.txt"},
	}
	for _, test := range tests {
		for _, home := range []string{"/home/alice", ""} {
			t.Run(test.name+"/home="+home, func(t *testing.T) {
				input := Input{
					Tool:        "shell",
					Command:     test.command,
					CWD:         "/repo",
					ActiveHome:  home,
					DialectHint: DialectPOSIX,
				}
				facts := Analyze(input)
				before := Analyze(input)
				reduced, ok := facts.DynamicRedirectTargetReduction()
				if ok != test.reduced {
					t.Fatalf("reduced = %t, want %t; parse=%+v commands=%+v",
						ok, test.reduced, facts.Parse, facts.Commands)
				}
				if !reflect.DeepEqual(facts, before) {
					t.Fatal("reduction changed its input")
				}
				if !ok {
					if !reflect.DeepEqual(reduced, Facts{}) {
						t.Fatalf("declined reduction returned facts: %+v", reduced)
					}
					return
				}
				if facts.Authoritative() || !reduced.Authoritative() ||
					len(reduced.Parse.Issues) != 0 ||
					reduced.Parse.Dialect != facts.Parse.Dialect {
					t.Fatalf("parse: action=%+v view=%+v", facts.Parse, reduced.Parse)
				}
				if !reduced.EnforcementEligible() {
					t.Fatalf("view is not enforcement eligible: %+v", reduced.Commands)
				}
				if len(reduced.Commands) != len(facts.Commands) {
					t.Fatalf("view has %d commands, action %d", len(reduced.Commands), len(facts.Commands))
				}
				for index, command := range reduced.Commands {
					if !command.ArgvComplete ||
						!reflect.DeepEqual(command.Argv, facts.Commands[index].Argv) {
						t.Fatalf("command %d argv changed: %+v", index, command)
					}
					for _, redirect := range command.Redirects {
						if redirect.Expands || redirect.Target == "" {
							t.Fatalf("command %d kept a dynamic redirect: %+v", index, command.Redirects)
						}
					}
				}
				if got := len(reduced.Commands[0].Redirects); got != test.kept {
					t.Fatalf("first command kept %d redirects, want %d", got, test.kept)
				}
				if !reflect.DeepEqual(reduced.Paths, facts.Paths) ||
					!reflect.DeepEqual(reduced.DataFlows, facts.DataFlows) ||
					!reflect.DeepEqual(reduced.Network, facts.Network) {
					t.Fatal("view changed path, data-flow or network facts")
				}
				for _, path := range reduced.Paths {
					if path.Value == "" {
						t.Fatalf("view invented a path for a dropped target: %+v", reduced.Paths)
					}
				}
			})
		}
	}
}
