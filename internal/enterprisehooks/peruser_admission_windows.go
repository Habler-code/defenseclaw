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

//go:build windows

package enterprisehooks

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// Per-user connectors whose setup binds to a protected, setup-selected
// executable (Amp, OpenCode, Hermes on Windows) need an exact native image the
// LocalSystem guardian can hash as the target user. These are the only images
// the guardian selects; anything else stays unmanaged and is reported, rather
// than failing the reconcile for every other user.
var windowsStandaloneManagedExecutableRelative = map[string][]string{
	// npm's amp.cmd launches this native image.
	"amp": {"AppData", "Roaming", "npm", "node_modules", "@ampcode", "cli", "bin", "amp.exe"},
	// The connector's executable admission accepts only the official SST
	// WinGet image.
	"opencode": {"AppData", "Local", "Microsoft", "WinGet", "Packages",
		"SST.opencode_Microsoft.Winget.Source_8wekyb3d8bbwe", "opencode.exe"},
}

// windowsStandalonePerUserManagedExecutable returns the native image the
// guardian binds a per-user connector's executable admission to, or a reason
// the install cannot be managed. Connectors without protected executable
// admission return ("", "").
func windowsStandalonePerUserManagedExecutable(profileHome, connectorName string) (string, string) {
	if !connector.ProtectedSetupSelectionConnector(connectorName) {
		return "", ""
	}
	switch connectorName {
	case "amp":
		// The guardian can now select and admit the native image, but the
		// Amp plugin's per-user custody (user-owned plugin directory holding
		// the hook API token) does not pass the managed token-path trust
		// check, so a live reconcile cannot verify coverage.
		return "", "managed Amp is not supported on Windows yet: its per-user plugin token custody does not pass the managed verification"
	case "hermes":
		return "", "managed Hermes is not supported on Windows yet: its executable admission runs the Hermes version probe, which the LocalSystem guardian does not launch as the user"
	case "opencode":
		relative := windowsStandaloneManagedExecutableRelative[connectorName]
		candidate := filepath.Join(append([]string{profileHome}, relative...)...)
		if err := winpath.RejectReparseChain(filepath.Dir(candidate)); err != nil {
			return "", fmt.Sprintf("the %s install path is not a plain directory chain: %v", connectorName, err)
		}
		info, err := os.Lstat(candidate)
		if err != nil || !info.Mode().IsRegular() {
			return "", "managed OpenCode requires the official SST WinGet package (winget install SST.opencode); other installs are not admitted"
		}
		return candidate, ""
	default:
		return "", fmt.Sprintf("connector %s has no managed executable selection on Windows", connectorName)
	}
}

// windowsStandalonePerUserAdmission reports whether the guardian can manage a
// per-user connector install for one user: the discovered version must have a
// known hook contract and any protected executable must be present. Rows that
// fail are skipped by the enumerator with the returned reason, so one user's
// unsupported install cannot fail the reconcile for everyone else.
func windowsStandalonePerUserAdmission(profileHome, connectorName, version string) (bool, string) {
	if _, perUser := windowsStandalonePerUserConnector(connectorName); !perUser {
		return true, ""
	}
	if resolution := connector.ResolveHookContract(connectorName, version); resolution.Status != connector.HookCompatibilityKnown {
		return false, fmt.Sprintf("version %s is not verified against a known hook contract", version)
	}
	if _, reason := windowsStandalonePerUserManagedExecutable(profileHome, connectorName); reason != "" {
		return false, reason
	}
	return true, ""
}
