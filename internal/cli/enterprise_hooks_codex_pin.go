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
	"encoding/json"
	"fmt"
	"runtime"
	"strings"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// On macOS managed endpoints DefenseClaw's Codex hooks are user-level, so the
// guardian also publishes a machine requirements pin ([features] hooks = true)
// that keeps Codex hooks enabled regardless of user configuration. Native
// Windows already publishes that pin with its managed hook matrix.
var (
	enterpriseHookCodexPinSupported = func() bool { return runtime.GOOS == "darwin" }
	enterpriseHookCodexPinEnsure    = enterprisehooks.EnsureCodexRequirementsHooksPin
	enterpriseHookCodexPinRemove    = enterprisehooks.RemoveCodexRequirementsHooksPin
	enterpriseHookCodexPinInspect   = enterprisehooks.InspectCodexRequirementsHooksPin
)

func enterpriseHookCodexPinApplies() bool {
	return enterpriseHookCodexPinSupported() &&
		cfg != nil &&
		managed.IsManagedEnterprise(cfg.DeploymentMode)
}

func enterpriseHookManifestHasEnabledConnector(manifest enterprisehooks.Manifest, name string) bool {
	for _, target := range manifest.Targets {
		if target.IsEnabled() && strings.EqualFold(strings.TrimSpace(target.Connector), name) {
			return true
		}
	}
	return false
}

// reconcileEnterpriseHookCodexPin publishes the pin while the manifest has an
// enabled Codex target and retires DefenseClaw's pin when it has none. A
// publication failure is returned as err because it leaves the Codex targets
// unprotected; a retirement failure is only a warning, since a leftover pin
// only keeps Codex hooks enabled.
func reconcileEnterpriseHookCodexPin(manifest enterprisehooks.Manifest) (warning string, err error) {
	if !enterpriseHookCodexPinApplies() {
		return "", nil
	}
	if enterpriseHookManifestHasEnabledConnector(manifest, "codex") {
		if _, err := enterpriseHookCodexPinEnsure(); err != nil {
			return "", fmt.Errorf("publish the Codex machine requirements hooks pin: %w", err)
		}
		return "", nil
	}
	if _, err := enterpriseHookCodexPinRemove(); err != nil {
		return fmt.Sprintf("retire the Codex machine requirements hooks pin: %v", err), nil
	}
	return "", nil
}

// enterpriseHookCodexPinOutcome is one reconcile pass's pin result. The pin is
// published before the targets are processed, so a Codex setup in the same
// pass already runs under it.
type enterpriseHookCodexPinOutcome struct {
	warning string
	err     error
}

func reconcileEnterpriseHookCodexPinOutcome(manifest enterprisehooks.Manifest) enterpriseHookCodexPinOutcome {
	warning, err := reconcileEnterpriseHookCodexPin(manifest)
	return enterpriseHookCodexPinOutcome{warning: warning, err: err}
}

// applyToRows fails every successful Codex row with a publication failure
// (counted in failures). When no row can carry the failure it is returned as a
// warning, together with any retirement warning.
func (o enterpriseHookCodexPinOutcome) applyToRows(rows []enterpriseHookReconcileRow, failures *int) []string {
	var warnings []string
	if o.warning != "" {
		warnings = append(warnings, o.warning)
	}
	if marked := markEnterpriseHookCodexPinRows(rows, o.err); marked > 0 {
		*failures += marked
	} else if o.err != nil {
		warnings = append(warnings, o.err.Error())
	}
	return warnings
}

// verifyEnterpriseHookCodexPin requires the pin, from DefenseClaw or the
// administrator, whenever the manifest has an enabled Codex target.
func verifyEnterpriseHookCodexPin(manifest enterprisehooks.Manifest) error {
	if !enterpriseHookCodexPinApplies() ||
		!enterpriseHookManifestHasEnabledConnector(manifest, "codex") {
		return nil
	}
	result, err := enterpriseHookCodexPinInspect()
	if err != nil {
		return fmt.Errorf("inspect the Codex machine requirements hooks pin: %w", err)
	}
	if result.State == enterprisehooks.CodexRequirementsPinAbsent {
		return fmt.Errorf(
			"Codex machine requirements %s do not pin [features] hooks = true, so users can turn Codex hooks off",
			result.Path,
		)
	}
	return nil
}

// markEnterpriseHookCodexPinRows fails every successful Codex row with the pin
// error and returns how many rows it failed. Pending rows are unchanged.
func markEnterpriseHookCodexPinRows(rows []enterpriseHookReconcileRow, pinErr error) int {
	if pinErr == nil {
		return 0
	}
	failed := 0
	for index := range rows {
		row := &rows[index]
		if !row.OK || !strings.EqualFold(strings.TrimSpace(row.Connector), "codex") {
			continue
		}
		row.OK = false
		row.Result = nil
		row.Error = pinErr.Error()
		failed++
	}
	return failed
}

var enterpriseHooksCodexPinJSON bool

var enterpriseHooksCodexPinCmd = &cobra.Command{
	Use:    "codex-requirements-pin",
	Short:  "Inspect, publish, or remove the Codex machine requirements hooks pin",
	Hidden: true,
	Long: `Manage DefenseClaw's [features] hooks = true pin in the machine Codex
requirements (/etc/codex/requirements.toml) on macOS and Linux. The guardian
publishes it while a Codex target is enabled; the macOS uninstaller removes it.
Only the DefenseClaw-owned key is added or removed; administrator content is
preserved.`,
}

func newEnterpriseHooksCodexPinAction(action string, run func() (enterprisehooks.CodexRequirementsPinResult, error)) *cobra.Command {
	command := &cobra.Command{
		Use:          action,
		Short:        action + " the Codex machine requirements hooks pin",
		Hidden:       true,
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		Annotations: map[string]string{
			// Uninstall runs remove on hosts where config.yaml may already be
			// unreadable; the pin does not depend on DefenseClaw config.
			"defenseclaw.skip-daemon-bootstrap": "true",
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			result, err := run()
			if enterpriseHooksCodexPinJSON {
				payload := map[string]any{"ok": err == nil, "result": result}
				if err != nil {
					payload["error"] = err.Error()
				}
				if encodeErr := json.NewEncoder(cmd.OutOrStdout()).Encode(payload); encodeErr != nil && err == nil {
					err = encodeErr
				}
			} else if err == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Codex machine requirements hooks pin %s: %s (path=%s, changed=%t, removed_file=%t)\n",
					action, result.State, result.Path, result.Changed, result.RemovedFile)
			}
			return err
		},
	}
	command.Flags().BoolVar(&enterpriseHooksCodexPinJSON, "json", false, "Emit machine-readable JSON")
	return command
}

func init() {
	enterpriseHooksCodexPinCmd.AddCommand(
		newEnterpriseHooksCodexPinAction("status", func() (enterprisehooks.CodexRequirementsPinResult, error) {
			return enterpriseHookCodexPinInspect()
		}),
		newEnterpriseHooksCodexPinAction("ensure", func() (enterprisehooks.CodexRequirementsPinResult, error) {
			return enterpriseHookCodexPinEnsure()
		}),
		newEnterpriseHooksCodexPinAction("remove", func() (enterprisehooks.CodexRequirementsPinResult, error) {
			return enterpriseHookCodexPinRemove()
		}),
	)
	enterpriseHooksCmd.AddCommand(enterpriseHooksCodexPinCmd)
}
