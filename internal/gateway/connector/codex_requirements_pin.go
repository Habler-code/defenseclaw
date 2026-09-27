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

package connector

import (
	"runtime"

	"github.com/pelletier/go-toml/v2"
)

// codexUserHooksFeaturePinned reports whether a managed macOS or Linux setup
// runs under machine Codex requirements that pin [features] hooks = true.
// Codex then keeps hooks enabled whatever the user's config.toml says, so a
// user-level [features] hooks = false is inactive: Setup still repairs the
// DefenseClaw hooks and the guardian does not treat the flag as removal. It
// is replaceable only by package tests.
var codexUserHooksFeaturePinned = func(opts SetupOpts) bool {
	if !opts.ManagedEnterprise || runtime.GOOS == "windows" {
		return false
	}
	path, err := codexSystemRequirementsPathForInspection()
	if err != nil {
		return false
	}
	raw, exists, err := readCodexSystemRequirements(path, true)
	if err != nil || !exists || len(raw) > codexPolicyMessageLimit {
		return false
	}
	return codexRequirementsPinHooks(raw)
}

// codexUserHooksFlagInactive reports whether a user-level [features] key set
// to false leaves Codex hooks on because the machine requirements pin
// hooks = true. Only the hooks key qualifies. Codex 0.124 through 0.128 (hook
// contract codex-hooks-v1) name the feature codex_hooks and skip a hooks
// requirement they do not know, so there a user codex_hooks = false still
// turns hooks off while hooks = false is itself ignored; from 0.129 the pin
// covers both. Treating codex_hooks = false as active is therefore right for
// every supported build, and the user can resolve it by deleting the
// deprecated key.
func codexUserHooksFlagInactive(key string, hooksPinned bool) bool {
	return hooksPinned && key == "hooks"
}

// codexRequirementsPinHooks reports whether a requirements document sets
// [features] hooks = true.
func codexRequirementsPinHooks(raw []byte) bool {
	var requirements struct {
		Features map[string]interface{} `toml:"features"`
	}
	if err := toml.Unmarshal(raw, &requirements); err != nil {
		return false
	}
	enabled, ok := requirements.Features["hooks"].(bool)
	return ok && enabled
}
