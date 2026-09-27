// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	policyassets "github.com/defenseclaw/defenseclaw/policies"
)

// DefaultConfig is the configuration a fresh standalone install gets when
// the administrator supplies none: local policy engine in observe mode, no
// connectors, loopback listeners. Administrators replace it through their
// MDM; the apply unit or `ensure` activates the change.
func DefaultConfig(layout managed.StandaloneLayout) []byte {
	return []byte(fmt.Sprintf(`# DefenseClaw managed enterprise configuration (standalone profile).
# Administrator-owned. Edit through your MDM or configuration management;
# the lifecycle validates and applies every change.
config_version: 8
deployment_mode: managed_enterprise
data_dir: %s
policy_dir: %s
enterprise:
  profile: standalone
gateway:
  api_bind: 127.0.0.1
  api_port: 18970
guardrail:
  enabled: true
  mode: observe
  rule_pack_dir: %s
`, layout.DataDir, layout.VendorPolicyDir, path.Join(layout.VendorPolicyDir, "guardrail", "default")))
}

// validatedConfig is an administrator config that passed every lifecycle
// check, with the settings the lifecycle renders from.
type validatedConfig struct {
	Raw                    []byte
	SHA                    string
	Connectors             []string
	HomeRoots              []string
	AgentPrefixes          []string
	HTTPSProxy             string
	NoProxy                string
	SelfUpdateDisabled     bool
	MachinePolicyOwnership map[string]string
	// Loaded is the runtime config the checks loaded; machine policy is
	// published from it.
	Loaded *config.Config
}

// envPinMu serializes the temporary process-environment pins validation
// needs: the config loader reads the service pins from the environment.
var envPinMu sync.Mutex

// validateConfig checks raw as the standalone deployment's config: v8
// schema, observability graph, runtime load with the service pins, and the
// fixed layout the units assume.
func (e *Env) validateConfig(raw []byte) (*validatedConfig, error) {
	if len(raw) == 0 {
		return nil, errors.New("config is empty")
	}
	if len(raw) > config.ObservabilityV8MaxSourceBytes {
		return nil, fmt.Errorf("config exceeds %d bytes", config.ObservabilityV8MaxSourceBytes)
	}
	path := e.Layout.ConfigPath

	envPinMu.Lock()
	restore := pinEnv(map[string]string{
		managed.DeploymentModeEnv:    managed.DeploymentModeManagedEnterprise,
		managed.EnterpriseProfileEnv: managed.ProfileStandalone,
	})
	compiled, compileErr := config.ParseCompileObservabilityV8(path, raw, config.ObservabilityV8CompileOptions{DefaultDataDir: e.Layout.DataDir})
	cfg, loadErr := config.LoadRuntimeV8InspectionCandidateFromBytes(path, raw)
	restore()
	envPinMu.Unlock()

	if compileErr != nil {
		return nil, fmt.Errorf("config does not compile: %w", compileErr)
	}
	if compiled == nil || compiled.Plan == nil {
		return nil, errors.New("config compiled to no observability plan")
	}
	if loadErr != nil {
		return nil, fmt.Errorf("config does not load: %w", loadErr)
	}
	if !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return nil, fmt.Errorf("config deployment_mode must be %s", managed.DeploymentModeManagedEnterprise)
	}
	if !cfg.StandaloneEnterprise() {
		return nil, fmt.Errorf("config enterprise.profile must be %s", managed.ProfileStandalone)
	}
	if clean := strings.TrimRight(cfg.DataDir, "/"); clean != e.Layout.DataDir {
		return nil, fmt.Errorf("config data_dir %q must be %s: the service sandbox only allows writes there", cfg.DataDir, e.Layout.DataDir)
	}
	if bind := strings.TrimSpace(cfg.Gateway.APIBind); bind != "" && bind != "127.0.0.1" {
		return nil, fmt.Errorf("config gateway.api_bind %q must be 127.0.0.1", bind)
	}
	if port := cfg.Gateway.APIPort; port != 0 && port != 18970 {
		return nil, fmt.Errorf("config gateway.api_port %d must be 18970: the socket unit owns that listener", port)
	}
	if err := e.checkRulePackDirs(cfg); err != nil {
		return nil, err
	}
	v := &validatedConfig{
		Raw:                    append([]byte(nil), raw...),
		SHA:                    sha256Bytes(raw),
		HomeRoots:              append([]string{}, cfg.Enterprise.Enrollment.HomeRoots...),
		AgentPrefixes:          append([]string{}, cfg.Enterprise.Enrollment.AgentPrefixes...),
		HTTPSProxy:             strings.TrimSpace(cfg.Enterprise.Network.HTTPSProxy),
		NoProxy:                strings.TrimSpace(cfg.Enterprise.Network.NoProxy),
		SelfUpdateDisabled:     cfg.Enterprise.Coexistence.SelfUpdateDisabled(),
		MachinePolicyOwnership: map[string]string{},
		Loaded:                 cfg,
	}
	for name := range cfg.Guardrail.Connectors {
		connector := strings.ToLower(strings.TrimSpace(name))
		if connector == "" || !cfg.Guardrail.EffectiveEnabled(name) {
			continue
		}
		v.Connectors = append(v.Connectors, connector)
		v.MachinePolicyOwnership[connector] = cfg.Enterprise.MachinePolicy.PolicyFor(connector).Ownership
	}
	sort.Strings(v.Connectors)
	sort.Strings(v.HomeRoots)
	sort.Strings(v.AgentPrefixes)
	return v, nil
}

// checkRulePackDirs refuses rule packs the gateway cannot load or could
// rewrite itself: every effective rule pack must be outside data_dir and
// either ship with the vendor policies or already exist.
func (e *Env) checkRulePackDirs(cfg *config.Config) error {
	dirs := map[string]string{"guardrail.rule_pack_dir": cfg.Guardrail.RulePackDir}
	for name := range cfg.Guardrail.Connectors {
		dirs["guardrail.connectors."+name+".rule_pack_dir"] = cfg.EffectiveRulePackDirForConnector(name)
	}
	vendor, err := policyassets.Files()
	if err != nil {
		return fmt.Errorf("embedded vendor policies: %w", err)
	}
	for _, label := range sortedKeys(dirs) {
		dir := strings.TrimSpace(dirs[label])
		if dir == "" {
			continue
		}
		clean := filepath.Clean(dir)
		if clean == e.Layout.DataDir || strings.HasPrefix(clean, e.Layout.DataDir+"/") {
			return fmt.Errorf("config %s %q is inside data_dir, which the gateway service can write; use %s or an administrator-owned directory under %s", label, dir, filepath.Join(e.Layout.VendorPolicyDir, "guardrail", "default"), e.Layout.PolicyDir)
		}
		if rel, ok := strings.CutPrefix(clean, e.Layout.VendorPolicyDir+"/"); ok {
			if !vendorPolicyDirExists(vendor, filepath.ToSlash(rel)) {
				return fmt.Errorf("config %s %q is not a rule pack the product ships", label, dir)
			}
			continue
		}
		if info, err := os.Stat(e.P(clean)); err != nil || !info.IsDir() {
			return fmt.Errorf("config %s %q does not exist; install the rule pack first or use %s", label, dir, filepath.Join(e.Layout.VendorPolicyDir, "guardrail", "default"))
		}
	}
	return nil
}

func vendorPolicyDirExists(files []policyassets.File, rel string) bool {
	for _, file := range files {
		if strings.HasPrefix(file.Path, rel+"/") {
			return true
		}
	}
	return false
}

// machinePolicyEnabled lists connectors that publish machine policy.
func (v *validatedConfig) machinePolicyEnabled(goos string) []string {
	candidates := []string{}
	for _, connector := range v.Connectors {
		if v.MachinePolicyOwnership[connector] != config.MachinePolicyOwnershipOff {
			candidates = append(candidates, connector)
		}
	}
	return MachinePolicyConnectors(goos, candidates)
}

func pinEnv(values map[string]string) func() {
	previous := map[string]*string{}
	for key, value := range values {
		if old, ok := os.LookupEnv(key); ok {
			copyOld := old
			previous[key] = &copyOld
		} else {
			previous[key] = nil
		}
		_ = os.Setenv(key, value)
	}
	return func() {
		for key, old := range previous {
			if old == nil {
				_ = os.Unsetenv(key)
			} else {
				_ = os.Setenv(key, *old)
			}
		}
	}
}
