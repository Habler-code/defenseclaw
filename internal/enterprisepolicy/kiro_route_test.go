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

package enterprisepolicy

import (
	"strings"
	"testing"
)

// Kiro's route must say what the guardian does with it. The Linux and macOS
// guardians enroll Kiro per user (the hook goes into each user's global
// ~/.kiro/hooks), so reporting ACP there told administrators Kiro was
// protected only through the ACP guard. The Windows guardian refuses Kiro,
// so it stays on ACP there.
func TestKiroRouteFollowsItsEnrollment(t *testing.T) {
	for goos, want := range map[string]string{
		"linux":   RoutePerUser,
		"darwin":  RoutePerUser,
		"windows": RouteACP,
	} {
		if got := RouteFor("kiro", goos); got != want {
			t.Errorf("RouteFor(kiro, %s) = %q, want %q", goos, got, want)
		}
	}
}

func TestKiroRouteStateNamesTheGlobalHookAndACP(t *testing.T) {
	opts := testOptions(t)
	result, err := VerifyAll(opts, []string{"kiro"})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.States) != 1 {
		t.Fatalf("states = %+v", result.States)
	}
	state := result.States[0]
	details := strings.Join(state.Details, "\n")
	if state.Route != RoutePerUser || !strings.Contains(details, "~/.kiro/hooks/defenseclaw.json") || !strings.Contains(details, "enterprise acp") {
		t.Fatalf("kiro state = %+v", state)
	}
	if state.Covered {
		t.Fatal("kiro is never covered by machine policy")
	}
}
