// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import "errors"

// Native Windows publishes [features] hooks = true together with the managed
// hook matrix through the protected machine requirements reconciler.
var errCodexRequirementsPinUnsupported = errors.New(
	"enterprise hooks: the standalone Codex requirements hooks pin is used only on macOS and Linux",
)

func InspectCodexRequirementsHooksPin() (CodexRequirementsPinResult, error) {
	return CodexRequirementsPinResult{}, errCodexRequirementsPinUnsupported
}

func EnsureCodexRequirementsHooksPin() (CodexRequirementsPinResult, error) {
	return CodexRequirementsPinResult{}, errCodexRequirementsPinUnsupported
}

func RemoveCodexRequirementsHooksPin() (CodexRequirementsPinResult, error) {
	return CodexRequirementsPinResult{}, errCodexRequirementsPinUnsupported
}
