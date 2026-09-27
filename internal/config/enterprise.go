// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/netguard"
)

// EnterpriseConfig selects and tunes the managed_enterprise profile. It is
// administrator-owned like the rest of a managed config; an enterprise
// block in a non-managed config is rejected.
type EnterpriseConfig struct {
	Profile       string                        `mapstructure:"profile"        yaml:"profile,omitempty"`
	Inspection    EnterpriseInspectionConfig    `mapstructure:"inspection"     yaml:"inspection,omitempty"`
	Enrollment    EnterpriseEnrollmentConfig    `mapstructure:"enrollment"     yaml:"enrollment,omitempty"`
	MachinePolicy EnterpriseMachinePolicyConfig `mapstructure:"machine_policy" yaml:"machine_policy,omitempty"`
	Trust         EnterpriseTrustConfig         `mapstructure:"trust"          yaml:"trust,omitempty"`
	Coexistence   EnterpriseCoexistenceConfig   `mapstructure:"coexistence"    yaml:"coexistence,omitempty"`
	Network       EnterpriseNetworkConfig       `mapstructure:"network"        yaml:"network,omitempty"`
}

// EnterpriseInspectionConfig chooses the optional remote inspection of a
// standalone deployment. Secure Client deployments always use CMID.
type EnterpriseInspectionConfig struct {
	AIDefense EnterpriseAIDefenseConfig `mapstructure:"ai_defense" yaml:"ai_defense,omitempty"`
}

// EnterpriseAIDefenseConfig names the protected credential that carries the
// Cisco AI Defense API key. The key itself never appears in config.
type EnterpriseAIDefenseConfig struct {
	Enabled    bool   `mapstructure:"enabled"    yaml:"enabled,omitempty"`
	Credential string `mapstructure:"credential" yaml:"credential,omitempty"`
}

// Enrollment modes and policies.
const (
	EnterpriseEnrollmentAuto     = "auto"
	EnterpriseEnrollmentManifest = "manifest"

	EnterpriseUnenrolledInspect = "inspect"
	EnterpriseUnenrolledDeny    = "deny"

	EnterpriseRootInspect = "inspect"
	EnterpriseRootDeny    = "deny"
	EnterpriseRootExempt  = "exempt"
)

// EnterpriseEnrollmentConfig controls which local users the enumerator
// enrolls and how the gateway treats users it has not enrolled.
type EnterpriseEnrollmentConfig struct {
	Mode            string   `mapstructure:"mode"             yaml:"mode,omitempty"`
	IncludeUsers    []string `mapstructure:"include_users"    yaml:"include_users,omitempty"`
	ExcludeUsers    []string `mapstructure:"exclude_users"    yaml:"exclude_users,omitempty"`
	IncludeGroups   []string `mapstructure:"include_groups"   yaml:"include_groups,omitempty"`
	ExcludeGroups   []string `mapstructure:"exclude_groups"   yaml:"exclude_groups,omitempty"`
	ExemptUsers     []string `mapstructure:"exempt_users"     yaml:"exempt_users,omitempty"`
	UnenrolledUsers string   `mapstructure:"unenrolled_users" yaml:"unenrolled_users,omitempty"`
	Root            string   `mapstructure:"root"             yaml:"root,omitempty"`
	// UIDMin overrides the unix login.defs UID_MIN; 0 means "read it".
	UIDMin int `mapstructure:"uid_min" yaml:"uid_min,omitempty"`
	// HomeRoots lists extra home parents (e.g. /srv/home) the guardian may
	// write under. The lifecycle widens the guardian unit to exactly these.
	HomeRoots []string `mapstructure:"home_roots" yaml:"home_roots,omitempty"`
	// AgentPrefixes lists extra administrator-owned install prefixes (for
	// example an npm prefix such as /opt/tools) where agent CLIs live. The
	// enumerator and guardian discover agents only in known locations, so
	// agents installed elsewhere are not enrolled without this.
	AgentPrefixes []string `mapstructure:"agent_prefixes" yaml:"agent_prefixes,omitempty"`
}

// Machine policy knobs.
const (
	MachinePolicyOwnershipMerge      = "merge"
	MachinePolicyOwnershipVerifyOnly = "verify_only"
	MachinePolicyOwnershipOff        = "off"

	ManagedHooksOnlyEnforce  = "enforce"
	ManagedHooksOnlyPreserve = "preserve"

	ForeignHooksRemove = "remove"
	ForeignHooksReport = "report"
	ForeignHooksAllow  = "allow"

	HigherPrecedenceFail = "fail"
	HigherPrecedenceWarn = "warn"
)

// EnterpriseConnectorPolicy is one connector's machine policy settings. An
// empty field inherits from the default block, then from the built-in
// secure defaults.
type EnterpriseConnectorPolicy struct {
	Ownership               string   `mapstructure:"ownership"                 yaml:"ownership,omitempty"`
	ManagedHooksOnly        string   `mapstructure:"managed_hooks_only"        yaml:"managed_hooks_only,omitempty"`
	ForeignHooks            string   `mapstructure:"foreign_hooks"             yaml:"foreign_hooks,omitempty"`
	HigherPrecedenceSources string   `mapstructure:"higher_precedence_sources" yaml:"higher_precedence_sources,omitempty"`
	AllowedHooks            []string `mapstructure:"allowed_hooks"             yaml:"allowed_hooks,omitempty"`
}

// EnterpriseMachinePolicyConfig holds the default connector policy and
// per-connector overrides.
type EnterpriseMachinePolicyConfig struct {
	Default    EnterpriseConnectorPolicy            `mapstructure:"default"    yaml:"default,omitempty"`
	Connectors map[string]EnterpriseConnectorPolicy `mapstructure:"connectors" yaml:"connectors,omitempty"`
}

// Trust modes for Windows standalone payload verification.
const (
	EnterpriseTrustAuthenticode = "authenticode"
	EnterpriseTrustHashPinned   = "hash_pinned"
)

// EnterpriseTrustConfig chooses how the lifecycle trusts payload files.
type EnterpriseTrustConfig struct {
	Mode           string   `mapstructure:"mode"            yaml:"mode,omitempty"`
	AllowedSigners []string `mapstructure:"allowed_signers" yaml:"allowed_signers,omitempty"`
}

// Coexistence with per-user installs.
const (
	PerUserInstallMigrate = "migrate"
	PerUserInstallBlock   = "block"
	PerUserInstallIgnore  = "ignore"
)

// EnterpriseCoexistenceConfig controls how a managed deployment treats an
// existing per-user DefenseClaw install.
type EnterpriseCoexistenceConfig struct {
	PerUserInstall    string `mapstructure:"per_user_install"    yaml:"per_user_install,omitempty"`
	DisableSelfUpdate *bool  `mapstructure:"disable_self_update" yaml:"disable_self_update,omitempty"`
}

// EnterpriseNetworkConfig is the gateway's egress proxy.
type EnterpriseNetworkConfig struct {
	HTTPSProxy string `mapstructure:"https_proxy" yaml:"https_proxy,omitempty"`
	NoProxy    string `mapstructure:"no_proxy"    yaml:"no_proxy,omitempty"`
}

// ResolvedConnectorPolicy is a connector's effective machine policy.
type ResolvedConnectorPolicy struct {
	Connector               string
	Ownership               string
	ManagedHooksOnly        string
	ForeignHooks            string
	HigherPrecedenceSources string
	AllowedHooks            []string
}

// builtinConnectorPolicy is the secure default: DefenseClaw merges its own
// entries, locks the agent to managed hooks where the vendor supports it,
// removes foreign user-level hooks that could rewrite input, and refuses
// to claim coverage under a higher-precedence policy source it cannot see.
var builtinConnectorPolicy = EnterpriseConnectorPolicy{
	Ownership:               MachinePolicyOwnershipMerge,
	ManagedHooksOnly:        ManagedHooksOnlyEnforce,
	ForeignHooks:            ForeignHooksRemove,
	HigherPrecedenceSources: HigherPrecedenceFail,
}

// PolicyFor returns connector's effective policy: connector override, then
// the default block, then the built-in secure defaults.
func (m EnterpriseMachinePolicyConfig) PolicyFor(connector string) ResolvedConnectorPolicy {
	connector = strings.ToLower(strings.TrimSpace(connector))
	pick := func(values ...string) string {
		for _, value := range values {
			if value = strings.ToLower(strings.TrimSpace(value)); value != "" {
				return value
			}
		}
		return ""
	}
	override := m.Connectors[connector]
	resolved := ResolvedConnectorPolicy{
		Connector:               connector,
		Ownership:               pick(override.Ownership, m.Default.Ownership, builtinConnectorPolicy.Ownership),
		ManagedHooksOnly:        pick(override.ManagedHooksOnly, m.Default.ManagedHooksOnly, builtinConnectorPolicy.ManagedHooksOnly),
		ForeignHooks:            pick(override.ForeignHooks, m.Default.ForeignHooks, builtinConnectorPolicy.ForeignHooks),
		HigherPrecedenceSources: pick(override.HigherPrecedenceSources, m.Default.HigherPrecedenceSources, builtinConnectorPolicy.HigherPrecedenceSources),
	}
	allowed := append([]string{}, m.Default.AllowedHooks...)
	allowed = append(allowed, override.AllowedHooks...)
	resolved.AllowedHooks = normalizeHookDigests(allowed)
	return resolved
}

func normalizeHookDigests(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(value), "sha256:"))
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

// EnterpriseProfile is the effective profile of a managed deployment, or ""
// when the deployment is not managed. The loader resolves the per-OS
// default and stores it; a managed Config built without the loader keeps
// the historical Secure Client posture, so no code path silently gains or
// loses local detectors because it skipped resolution.
func (c *Config) EnterpriseProfile() string {
	if c == nil || !managed.IsManagedEnterprise(c.DeploymentMode) {
		return ""
	}
	if profile := managed.NormalizeEnterpriseProfile(c.Enterprise.Profile); profile != "" {
		return profile
	}
	return managed.ProfileSecureClient
}

// ManagedAIDOnly reports the Secure Client decision posture: Cisco AI
// Defense (CMID) is the only decision-maker and local detectors are off.
func (c *Config) ManagedAIDOnly() bool {
	return managed.IsSecureClientProfile(c.EnterpriseProfile())
}

// SecureClientIntegration reports whether the Secure Client integration
// surfaces (GUI IPC, env_config overlay, CMID telemetry sink) are active.
func (c *Config) SecureClientIntegration() bool {
	return managed.IsSecureClientProfile(c.EnterpriseProfile())
}

// StandaloneEnterprise reports a managed deployment on the standalone
// profile, where the local policy engine decides.
func (c *Config) StandaloneEnterprise() bool {
	return managed.IsStandaloneProfile(c.EnterpriseProfile())
}

// SelfUpdateDisabled reports whether a managed deployment turns off the
// per-user installers and update notices (default true).
func (e EnterpriseCoexistenceConfig) SelfUpdateDisabled() bool {
	return e.DisableSelfUpdate == nil || *e.DisableSelfUpdate
}

var (
	enterpriseConnectorNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	enterpriseSHA256Pattern        = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// ValidEnterpriseCredentialName reports whether name is a safe protected
// credential name (it becomes a file name under the secrets directory).
func ValidEnterpriseCredentialName(name string) bool {
	return managed.ValidCredentialName(name)
}

// resolveEnterpriseConfig resolves the profile against the service pin and
// validates the enterprise block. goos is injected for tests.
func resolveEnterpriseConfig(cfg *Config, goos, pinnedProfile string) error {
	profile, err := managed.ResolveEnterpriseProfile(goos, cfg.DeploymentMode, pinnedProfile, cfg.Enterprise.Profile)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		if !enterpriseBlockEmpty(cfg.Enterprise) {
			return fmt.Errorf("config: the enterprise block requires deployment_mode %s", managed.DeploymentModeManagedEnterprise)
		}
		return nil
	}
	cfg.Enterprise.Profile = profile
	if cfg.StandaloneEnterprise() {
		standaloneRulePackDefault(cfg, cfg.DataDir)
	}
	return validateEnterpriseConfig(cfg)
}

// standaloneRulePackDefault keeps the default rule pack inside policy_dir.
// The loader's generic default lives under data_dir, which the standalone
// gateway service can write, so in the standalone profile that path always
// maps to the pack a per-user install would seed in policy_dir.
func standaloneRulePackDefault(cfg *Config, dataDir string) {
	implicit := filepath.Join(dataDir, "policies", "guardrail", "default")
	if cfg.Guardrail.RulePackDir != implicit || strings.TrimSpace(cfg.PolicyDir) == "" ||
		filepath.Clean(cfg.PolicyDir) == filepath.Join(dataDir, "policies") {
		return
	}
	cfg.Guardrail.RulePackDir = filepath.Join(cfg.PolicyDir, "guardrail", "default")
}

func enterpriseBlockEmpty(e EnterpriseConfig) bool {
	return strings.TrimSpace(e.Profile) == "" &&
		!e.Inspection.AIDefense.Enabled && strings.TrimSpace(e.Inspection.AIDefense.Credential) == "" &&
		enrollmentEmpty(e.Enrollment) &&
		machinePolicyEmpty(e.MachinePolicy) &&
		strings.TrimSpace(e.Trust.Mode) == "" && len(e.Trust.AllowedSigners) == 0 &&
		strings.TrimSpace(e.Coexistence.PerUserInstall) == "" && e.Coexistence.DisableSelfUpdate == nil &&
		strings.TrimSpace(e.Network.HTTPSProxy) == "" && strings.TrimSpace(e.Network.NoProxy) == ""
}

func enrollmentEmpty(e EnterpriseEnrollmentConfig) bool {
	return strings.TrimSpace(e.Mode) == "" && len(e.IncludeUsers) == 0 && len(e.ExcludeUsers) == 0 &&
		len(e.IncludeGroups) == 0 && len(e.ExcludeGroups) == 0 && len(e.ExemptUsers) == 0 &&
		strings.TrimSpace(e.UnenrolledUsers) == "" && strings.TrimSpace(e.Root) == "" &&
		e.UIDMin == 0 && len(e.HomeRoots) == 0 && len(e.AgentPrefixes) == 0
}

func machinePolicyEmpty(m EnterpriseMachinePolicyConfig) bool {
	return connectorPolicyEmpty(m.Default) && len(m.Connectors) == 0
}

func connectorPolicyEmpty(p EnterpriseConnectorPolicy) bool {
	return strings.TrimSpace(p.Ownership) == "" && strings.TrimSpace(p.ManagedHooksOnly) == "" &&
		strings.TrimSpace(p.ForeignHooks) == "" && strings.TrimSpace(p.HigherPrecedenceSources) == "" &&
		len(p.AllowedHooks) == 0
}

// validateEnterpriseConfig checks a managed deployment's enterprise block.
// Secure Client deployments may only carry the profile itself: every other
// knob belongs to the standalone profile, so a Secure Client config keeps
// its exact pre-existing behavior.
func validateEnterpriseConfig(cfg *Config) error {
	e := cfg.Enterprise
	if managed.IsSecureClientProfile(e.Profile) {
		rest := e
		rest.Profile = ""
		if !enterpriseBlockEmpty(rest) {
			return fmt.Errorf("config: enterprise settings other than profile apply only to the %s profile", managed.ProfileStandalone)
		}
		return nil
	}
	ai := e.Inspection.AIDefense
	if ai.Enabled {
		if !ValidEnterpriseCredentialName(ai.Credential) {
			return fmt.Errorf("config: enterprise.inspection.ai_defense.credential %q must be a protected credential name (lowercase letters, digits and dashes)", ai.Credential)
		}
	} else if strings.TrimSpace(ai.Credential) != "" && !ValidEnterpriseCredentialName(ai.Credential) {
		return fmt.Errorf("config: enterprise.inspection.ai_defense.credential %q is not a valid credential name", ai.Credential)
	}
	// The key never lives in config: the gateway reads it from the named
	// protected credential and ignores cisco_ai_defense.api_key_env.
	if strings.TrimSpace(cfg.CiscoAIDefense.APIKey) != "" {
		return fmt.Errorf("config: managed standalone deployments read the AI Defense key from a protected credential (enterprise.inspection.ai_defense.credential); remove cisco_ai_defense.api_key")
	}
	en := e.Enrollment
	if err := oneOf("enterprise.enrollment.mode", en.Mode, EnterpriseEnrollmentAuto, EnterpriseEnrollmentManifest); err != nil {
		return err
	}
	if err := oneOf("enterprise.enrollment.unenrolled_users", en.UnenrolledUsers, EnterpriseUnenrolledInspect, EnterpriseUnenrolledDeny); err != nil {
		return err
	}
	if err := oneOf("enterprise.enrollment.root", en.Root, EnterpriseRootInspect, EnterpriseRootDeny, EnterpriseRootExempt); err != nil {
		return err
	}
	if en.UIDMin < 0 {
		return fmt.Errorf("config: enterprise.enrollment.uid_min must not be negative")
	}
	for _, root := range en.HomeRoots {
		if err := validateEnterpriseHomeRoot(root); err != nil {
			return err
		}
	}
	for _, prefix := range en.AgentPrefixes {
		if err := validateEnterpriseAgentPrefix(prefix); err != nil {
			return err
		}
	}
	for _, list := range []struct {
		name   string
		values []string
	}{
		{"include_users", en.IncludeUsers}, {"exclude_users", en.ExcludeUsers},
		{"include_groups", en.IncludeGroups}, {"exclude_groups", en.ExcludeGroups},
		{"exempt_users", en.ExemptUsers},
	} {
		for _, value := range list.values {
			if strings.TrimSpace(value) == "" || strings.ContainsAny(value, "\x00\r\n") {
				return fmt.Errorf("config: enterprise.enrollment.%s contains an empty or malformed entry", list.name)
			}
		}
	}
	if err := validateConnectorPolicy("enterprise.machine_policy.default", e.MachinePolicy.Default); err != nil {
		return err
	}
	for name, policy := range e.MachinePolicy.Connectors {
		if !enterpriseConnectorNamePattern.MatchString(name) {
			return fmt.Errorf("config: enterprise.machine_policy.connectors key %q is not a connector name", name)
		}
		if err := validateConnectorPolicy("enterprise.machine_policy.connectors."+name, policy); err != nil {
			return err
		}
	}
	if err := oneOf("enterprise.trust.mode", e.Trust.Mode, EnterpriseTrustAuthenticode, EnterpriseTrustHashPinned); err != nil {
		return err
	}
	for _, signer := range e.Trust.AllowedSigners {
		if !enterpriseSHA256Pattern.MatchString(strings.ToLower(strings.TrimSpace(signer))) {
			return fmt.Errorf("config: enterprise.trust.allowed_signers entry %q must be a SHA-256 certificate thumbprint", signer)
		}
	}
	if err := oneOf("enterprise.coexistence.per_user_install", e.Coexistence.PerUserInstall, PerUserInstallMigrate, PerUserInstallBlock, PerUserInstallIgnore); err != nil {
		return err
	}
	for _, proxy := range []struct{ name, value string }{
		{"https_proxy", e.Network.HTTPSProxy}, {"no_proxy", e.Network.NoProxy},
	} {
		if strings.ContainsAny(proxy.value, "\x00\r\n") {
			return fmt.Errorf("config: enterprise.network.%s is malformed", proxy.name)
		}
	}
	if strings.TrimSpace(e.Network.HTTPSProxy) != "" {
		if _, err := netguard.ParseEgressProxyURL(e.Network.HTTPSProxy); err != nil {
			return fmt.Errorf("config: enterprise.network.https_proxy: %w", err)
		}
	}
	return nil
}

// EgressProxy returns the administrator's outbound proxy for this managed
// deployment (enterprise.network). The zero value keeps the
// process-environment proxy behavior.
func (e EnterpriseConfig) EgressProxy() netguard.EgressProxy {
	return netguard.EgressProxy{
		HTTPSProxy: strings.TrimSpace(e.Network.HTTPSProxy),
		NoProxy:    strings.TrimSpace(e.Network.NoProxy),
	}
}

func validateConnectorPolicy(prefix string, p EnterpriseConnectorPolicy) error {
	if err := oneOf(prefix+".ownership", p.Ownership, MachinePolicyOwnershipMerge, MachinePolicyOwnershipVerifyOnly, MachinePolicyOwnershipOff); err != nil {
		return err
	}
	if err := oneOf(prefix+".managed_hooks_only", p.ManagedHooksOnly, ManagedHooksOnlyEnforce, ManagedHooksOnlyPreserve); err != nil {
		return err
	}
	if err := oneOf(prefix+".foreign_hooks", p.ForeignHooks, ForeignHooksRemove, ForeignHooksReport, ForeignHooksAllow); err != nil {
		return err
	}
	if err := oneOf(prefix+".higher_precedence_sources", p.HigherPrecedenceSources, HigherPrecedenceFail, HigherPrecedenceWarn); err != nil {
		return err
	}
	for _, digest := range p.AllowedHooks {
		value := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(digest), "sha256:"))
		if !enterpriseSHA256Pattern.MatchString(value) {
			return fmt.Errorf("config: %s.allowed_hooks entry %q must be a SHA-256 digest", prefix, digest)
		}
	}
	return nil
}

// validateEnterpriseAgentPrefix accepts an absolute, administrator-style
// install prefix. User-writable trees are refused: an agent binary found
// there could be anything a user put there.
func validateEnterpriseAgentPrefix(prefix string) error {
	clean := strings.TrimSpace(prefix)
	if clean == "" || !strings.HasPrefix(clean, "/") || strings.Contains(clean, "..") ||
		strings.ContainsAny(clean, ":\x00\r\n") || filepath.Clean(clean) != clean {
		return fmt.Errorf("config: enterprise.enrollment.agent_prefixes entry %q must be a clean absolute path", prefix)
	}
	if clean == "/" {
		return fmt.Errorf("config: enterprise.enrollment.agent_prefixes entry %q is not an install prefix", prefix)
	}
	for _, forbidden := range []string{"/home", "/Users", "/tmp", "/var/tmp", "/dev/shm", "/private/tmp", "/root", "/var/root"} {
		if clean == forbidden || strings.HasPrefix(clean, forbidden+"/") {
			return fmt.Errorf("config: enterprise.enrollment.agent_prefixes entry %q is inside %s, which users can write", prefix, forbidden)
		}
	}
	return nil
}

func validateEnterpriseHomeRoot(root string) error {
	clean := strings.TrimSpace(root)
	if clean == "" || !strings.HasPrefix(clean, "/") || strings.Contains(clean, "..") || strings.ContainsAny(clean, "\x00\r\n") {
		return fmt.Errorf("config: enterprise.enrollment.home_roots entry %q must be an absolute path", root)
	}
	for _, forbidden := range []string{"/", "/tmp", "/var/tmp", "/dev/shm", "/etc", "/usr", "/bin", "/sbin", "/lib", "/opt", "/proc", "/sys", "/run", "/var"} {
		if strings.TrimRight(clean, "/") == forbidden || clean == forbidden {
			return fmt.Errorf("config: enterprise.enrollment.home_roots entry %q is not an allowed home parent", root)
		}
	}
	return nil
}

// validateManagedStandalonePolicyInputs requires every policy input the
// standalone local engine reads to be unwritable by standard users. The
// Secure Client profile never consults these (its local detectors are off),
// so the check applies only to standalone. Absent directories are fine:
// the engine falls back to its embedded rule packs.
func validateManagedStandalonePolicyInputs(cfg *Config) error {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return nil
	}
	serviceAccount := os.Getenv(managed.WindowsServiceAccountEnv)
	seen := map[string]bool{}
	check := func(label, dir string) error {
		dir = strings.TrimSpace(dir)
		if dir == "" || seen[dir] {
			return nil
		}
		seen[dir] = true
		if _, err := os.Lstat(dir); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return fmt.Errorf("config: inspect %s %s: %w", label, dir, err)
		}
		if err := managed.ValidateTrustedServiceRuntimeDir(dir, label, serviceAccount); err != nil {
			return fmt.Errorf("config: managed standalone %s is not administrator-controlled: %w", label, err)
		}
		return nil
	}
	if err := check("policy_dir", cfg.PolicyDir); err != nil {
		return err
	}
	if err := check("guardrail.rule_pack_dir", cfg.Guardrail.RulePackDir); err != nil {
		return err
	}
	names := make([]string, 0, len(cfg.Guardrail.Connectors))
	for name := range cfg.Guardrail.Connectors {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := check("guardrail.connectors."+name+".rule_pack_dir", cfg.EffectiveRulePackDirForConnector(name)); err != nil {
			return err
		}
	}
	return nil
}

func oneOf(name, value string, allowed ...string) error {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return nil
	}
	for _, candidate := range allowed {
		if value == candidate {
			return nil
		}
	}
	return fmt.Errorf("config: %s=%q is not one of %s", name, value, strings.Join(allowed, ", "))
}
