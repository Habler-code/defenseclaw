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

package config

import (
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/legacyconnector"
)

// migrateLegacyConnectorIDs moves retired connector IDs to their replacement
// everywhere a connector is named: guardrail.connector, claw.mode, the keys of
// every per-connector settings map (guardrail.connectors,
// asset_policy.connectors, application_protection.connectors,
// observability.connectors and connector_hooks) and the connector name lists
// (guardrail.judge.hook_connectors and
// application_protection.include_connectors / exclude_connectors). An
// explicit replacement entry wins; a list keeps one entry. It must run right
// after decoding and before normalizeConnectorKey or the duplicate-key check,
// so a config holding both the retired and the replacement key loads with the
// replacement's settings instead of failing. The notice names every setting
// that moved and every retired key that was dropped. The Python loader
// applies the same rule (defenseclaw.legacy_connector.migrate_raw_config).
func migrateLegacyConnectorIDs(cfg *Config) {
	if cfg == nil {
		return
	}
	var updated []string
	keys := make([]string, 0, len(cfg.Guardrail.Connectors))
	for key := range cfg.Guardrail.Connectors {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	primary, rename, dropped := legacyconnector.MigrateConnectorKeys(cfg.Guardrail.Connector, keys)
	if primary != cfg.Guardrail.Connector {
		updated = append(updated, "guardrail.connector")
	}
	if len(rename) > 0 || len(dropped) > 0 {
		updated = append(updated, "guardrail.connectors")
	}
	cfg.Guardrail.Connector = primary
	for old, replacement := range rename {
		cfg.Guardrail.Connectors[replacement] = cfg.Guardrail.Connectors[old]
		delete(cfg.Guardrail.Connectors, old)
	}
	for _, old := range dropped {
		delete(cfg.Guardrail.Connectors, old)
	}
	if mode, migrated := legacyconnector.Canonical(string(cfg.Claw.Mode)); migrated {
		cfg.Claw.Mode = ClawMode(mode)
		updated = append(updated, "claw.mode")
	}
	for _, other := range []struct {
		path    string
		migrate func() (bool, []string)
	}{
		{"asset_policy.connectors", func() (bool, []string) { return migrateLegacyConnectorMap(cfg.AssetPolicy.Connectors) }},
		{"application_protection.connectors", func() (bool, []string) {
			return migrateLegacyConnectorMap(cfg.ApplicationProtection.Connectors)
		}},
		{"observability.connectors", func() (bool, []string) { return migrateLegacyConnectorMap(cfg.Observability.Connectors) }},
		{"connector_hooks", func() (bool, []string) { return migrateLegacyConnectorMap(cfg.ConnectorHooks) }},
	} {
		moved, droppedKeys := other.migrate()
		if moved {
			updated = append(updated, other.path)
		}
		for _, key := range droppedKeys {
			dropped = append(dropped, other.path+"."+key)
		}
	}
	for _, list := range []struct {
		path   string
		values *[]string
	}{
		{"guardrail.judge.hook_connectors", &cfg.Guardrail.Judge.HookConnectors},
		{"application_protection.include_connectors", &cfg.ApplicationProtection.IncludeConnectors},
		{"application_protection.exclude_connectors", &cfg.ApplicationProtection.ExcludeConnectors},
	} {
		if migrateLegacyConnectorList(list.values) {
			updated = append(updated, list.path)
		}
	}
	if len(updated) > 0 {
		cfg.LegacyConnectorNotices = append(cfg.LegacyConnectorNotices, legacyConnectorNotice(cfg.ConfigFilePath, updated, dropped))
	}
}

// legacyConnectorNotice is legacyconnector.Notice naming the settings that
// moved: "moved connector X to Y in <settings> of <config> (kept ... and
// dropped ...)". The Python notice() builds the same text.
func legacyConnectorNotice(configPath string, updated, dropped []string) string {
	where := strings.TrimSpace(configPath)
	if where == "" {
		where = "config"
	}
	if len(updated) > 0 {
		where = strings.Join(updated, ", ") + " of " + where
	}
	return legacyconnector.Notice(where, dropped)
}

// migrateLegacyConnectorMap applies the rename rule to the keys of one
// per-connector settings map in place and reports whether it changed and
// which retired keys it dropped.
func migrateLegacyConnectorMap[T any](settings map[string]T) (bool, []string) {
	if len(settings) == 0 {
		return false, nil
	}
	keys := make([]string, 0, len(settings))
	for key := range settings {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	_, rename, dropped := legacyconnector.MigrateConnectorKeys("", keys)
	for old, replacement := range rename {
		settings[replacement] = settings[old]
		delete(settings, old)
	}
	for _, old := range dropped {
		delete(settings, old)
	}
	return len(rename) > 0 || len(dropped) > 0, dropped
}

// migrateLegacyConnectorList replaces retired IDs in one connector name list,
// in place, with their replacement at the first retired entry's position.
// When the replacement is already listed, or more than one retired entry is
// present, the extra entries are removed so the list names each connector
// once. It reports whether the list changed.
func migrateLegacyConnectorList(values *[]string) bool {
	if values == nil || len(*values) == 0 {
		return false
	}
	listed := false
	for _, value := range *values {
		if strings.EqualFold(strings.TrimSpace(value), legacyconnector.Replacement) {
			listed = true
		}
	}
	changed := false
	out := make([]string, 0, len(*values))
	for _, value := range *values {
		if !legacyconnector.IsRetired(value) {
			out = append(out, value)
			continue
		}
		changed = true
		if !listed {
			out = append(out, legacyconnector.Replacement)
			listed = true
		}
	}
	if changed {
		*values = out
	}
	return changed
}
