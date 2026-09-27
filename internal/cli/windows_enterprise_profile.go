// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

const (
	windowsEnterpriseTrustAuthenticode = "authenticode"
	windowsEnterpriseTrustHashPinned   = "hash_pinned"

	windowsEnterpriseConfigProfileLimit   = 4 << 20
	windowsEnterprisePayloadManifestLimit = 1 << 20
)

var (
	windowsEnterpriseDeploymentInspector = inspectTrustedWindowsEnterpriseDeployment
	windowsEnterpriseSHA256Pattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	windowsEnterprisePayloadLeafPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

	// Seams for inspectTrustedWindowsEnterpriseDeployment.
	windowsEnterpriseRecordRoots     = winpath.TrustedEnterpriseRoots
	windowsEnterpriseRecordInspector = winpath.InspectEnterpriseDeployment
	windowsEnterpriseRecordValidator = windowsEnterpriseRecordValidatorDefault
)

func windowsEnterpriseRecordValidatorDefault(path string) error {
	return managed.ValidateTrustedFilePath(path, "enterprise deployment record")
}

// inspectTrustedWindowsEnterpriseDeployment reads one profile's deployment
// record and honors it only when an administrator could have written it: the
// file and every ancestor are owned by SYSTEM, Administrators, or
// TrustedInstaller, no other principal can write the file, and none can
// replace an ancestor. The default ProgramData ACL lets a standard user create
// the other profile's vendor directory and plant a record there; such a record
// is reported absent, with Untrusted set, so it can neither block nor redirect
// an administrator's lifecycle. On a clean host, and for every record the
// lifecycle wrote, the result is unchanged. A standard user cannot read the
// protected record at all; for that caller an unverifiable record keeps its
// historical presence meaning, unless it is visibly not administrator-owned.
func inspectTrustedWindowsEnterpriseDeployment(profile string) (winpath.EnterpriseDeployment, error) {
	roots, err := windowsEnterpriseRecordRoots(profile)
	if err != nil {
		return winpath.EnterpriseDeployment{}, err
	}
	deployment, inspectErr := windowsEnterpriseRecordInspector(profile)
	if inspectErr == nil && deployment.State == winpath.EnterpriseDeploymentAbsent {
		return deployment, nil
	}
	validateErr := windowsEnterpriseRecordValidator(roots.MetadataPath)
	if validateErr == nil {
		return deployment, inspectErr
	}
	if errors.Is(validateErr, os.ErrPermission) && !windowsEnterpriseIsElevated() {
		return deployment, inspectErr
	}
	return winpath.EnterpriseDeployment{
		Profile:      roots.Profile,
		State:        winpath.EnterpriseDeploymentAbsent,
		MetadataPath: roots.MetadataPath,
		Untrusted:    validateErr.Error(),
	}, nil
}

// errWindowsEnterpriseInvalidArguments marks a preflight failure caused by
// the caller's arguments, which the standalone profile reports as 1639.
var errWindowsEnterpriseInvalidArguments = errors.New("invalid arguments")

func windowsEnterpriseInvalidArguments(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errWindowsEnterpriseInvalidArguments, fmt.Sprintf(format, args...))
}

// windowsEnterpriseStandalone reports whether the resolved lifecycle profile
// is standalone. Resolution runs before any action, so an unresolved
// profile is Secure Client.
func windowsEnterpriseStandalone(opts *windowsEnterpriseLifecycleOptions) bool {
	return opts != nil && managed.IsStandaloneProfile(opts.resolvedProfile)
}

// windowsEnterpriseCertificationScope reports whether the caller named a
// run-scoped certification deployment. Certification scopes use their own
// roots and service names, so production profile detection does not apply.
func windowsEnterpriseCertificationScope(opts *windowsEnterpriseLifecycleOptions) bool {
	return strings.TrimSpace(opts.installRoot) != "" ||
		strings.TrimSpace(opts.stateRoot) != "" ||
		strings.TrimSpace(opts.gatewayServiceName) != "" ||
		strings.TrimSpace(opts.guardianServiceName) != ""
}

// resolveWindowsEnterpriseLifecycleProfile selects the enterprise profile:
// --profile, then the supplied config's enterprise.profile, then the
// profile this host records as installed, then Secure Client. A request that names one
// profile while the other is installed is refused, because the profiles
// share SCM service names. A host with no standalone footprint and no
// request resolves to Secure Client with the historical arguments.
func resolveWindowsEnterpriseLifecycleProfile(action string, opts *windowsEnterpriseLifecycleOptions) error {
	requested := managed.NormalizeEnterpriseProfile(opts.profile)
	if requested != "" && requested != managed.ProfileSecureClient && requested != managed.ProfileStandalone {
		return windowsEnterpriseInvalidArguments("--profile must be %s or %s", managed.ProfileSecureClient, managed.ProfileStandalone)
	}
	if path := strings.TrimSpace(opts.configPath); path != "" {
		document, err := readWindowsEnterpriseConfigProfile(path)
		if err != nil {
			return err
		}
		configured := document.profile
		opts.configTrustMode, opts.configAllowedSigners = document.trustMode, document.allowedSigners
		if configured != "" {
			if requested != "" && requested != configured {
				return windowsEnterpriseInvalidArguments("--profile %s conflicts with enterprise.profile %s in %s", requested, configured, path)
			}
			requested = configured
		}
	}

	profile := requested
	if !windowsEnterpriseCertificationScope(opts) {
		// Only an installed (or unreadable) record selects or blocks a
		// profile. An uninstall tombstone never does: the unmodified Secure
		// Client Setup passes no --profile, so a leftover standalone
		// tombstone must not turn its install, status, or uninstall into a
		// standalone run. Standalone callers name --profile standalone.
		var live []string
		for _, candidate := range []string{managed.ProfileSecureClient, managed.ProfileStandalone} {
			deployment, err := windowsEnterpriseDeploymentInspector(candidate)
			if err != nil {
				return err
			}
			if deployment.Untrusted != "" {
				opts.ignoredDeploymentRecords = append(opts.ignoredDeploymentRecords,
					deployment.MetadataPath+": "+deployment.Untrusted)
			}
			switch deployment.State {
			case winpath.EnterpriseDeploymentInstalled, winpath.EnterpriseDeploymentUnknown:
				live = append(live, candidate)
			}
		}
		switch {
		case len(live) > 1:
			return errors.New("profile_conflict: both Secure Client and standalone enterprise deployments are recorded on this host")
		case len(live) == 1 && profile != "" && profile != live[0]:
			return fmt.Errorf(
				"profile_conflict: this host carries a %s enterprise deployment; %s of the %s profile is refused because the profiles share service names",
				live[0], action, profile,
			)
		case len(live) == 1:
			profile = live[0]
		}
	}
	if profile == "" {
		profile = managed.ProfileSecureClient
	}
	opts.resolvedProfile = profile
	return validateWindowsEnterpriseProfileOptions(action, opts)
}

func validateWindowsEnterpriseProfileOptions(action string, opts *windowsEnterpriseLifecycleOptions) error {
	standaloneOnly := strings.TrimSpace(opts.trustMode) != "" ||
		strings.TrimSpace(opts.payloadManifest) != "" ||
		len(opts.allowedSigners) != 0 ||
		strings.TrimSpace(opts.productVersion) != ""
	if !windowsEnterpriseStandalone(opts) {
		if standaloneOnly {
			return windowsEnterpriseInvalidArguments("--trust-mode, --payload-manifest, --allowed-signer, and --product-version apply only to the %s profile", managed.ProfileStandalone)
		}
		if action == "ensure" {
			return windowsEnterpriseInvalidArguments("ensure is available only for the %s profile", managed.ProfileStandalone)
		}
		return nil
	}
	if strings.TrimSpace(opts.brokerBinary) != "" {
		return windowsEnterpriseInvalidArguments("the %s profile has no CMID credential broker; omit --broker-binary", managed.ProfileStandalone)
	}
	if err := applyWindowsEnterpriseConfigTrust(opts); err != nil {
		return err
	}
	switch mode := strings.ToLower(strings.TrimSpace(opts.trustMode)); mode {
	case "", windowsEnterpriseTrustAuthenticode:
		opts.trustMode = windowsEnterpriseTrustAuthenticode
		if strings.TrimSpace(opts.payloadManifest) != "" {
			return windowsEnterpriseInvalidArguments("--payload-manifest applies only to --trust-mode %s", windowsEnterpriseTrustHashPinned)
		}
	case windowsEnterpriseTrustHashPinned:
		opts.trustMode = mode
		if strings.TrimSpace(opts.payloadManifest) == "" {
			return windowsEnterpriseInvalidArguments("--trust-mode %s requires --payload-manifest", windowsEnterpriseTrustHashPinned)
		}
	default:
		return windowsEnterpriseInvalidArguments("--trust-mode must be %s or %s", windowsEnterpriseTrustAuthenticode, windowsEnterpriseTrustHashPinned)
	}
	for index, signer := range opts.allowedSigners {
		normalized := strings.ToLower(strings.TrimSpace(signer))
		if !windowsEnterpriseSHA256Pattern.MatchString(normalized) {
			return windowsEnterpriseInvalidArguments("--allowed-signer %q is not a SHA-256 certificate thumbprint", signer)
		}
		opts.allowedSigners[index] = normalized
	}
	if strings.TrimSpace(opts.productVersion) == "" {
		opts.productVersion = strings.TrimSpace(appVersion)
	}
	return nil
}

// windowsEnterpriseConfigProfile is what profile and trust resolution read
// from an administrator-supplied config.
type windowsEnterpriseConfigProfile struct {
	profile        string
	trustMode      string
	allowedSigners []string
}

// readWindowsEnterpriseConfigProfile reads enterprise.profile and
// enterprise.trust from an administrator-supplied config. The lifecycle
// validates the whole file later; this only chooses which lifecycle
// validates it and, for the standalone profile, its payload trust.
func readWindowsEnterpriseConfigProfile(path string) (windowsEnterpriseConfigProfile, error) {
	file, err := os.Open(path)
	if err != nil {
		return windowsEnterpriseConfigProfile{}, fmt.Errorf("open managed config %s: %w", path, err)
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, windowsEnterpriseConfigProfileLimit+1))
	if err != nil {
		return windowsEnterpriseConfigProfile{}, fmt.Errorf("read managed config %s: %w", path, err)
	}
	if len(body) > windowsEnterpriseConfigProfileLimit {
		return windowsEnterpriseConfigProfile{}, fmt.Errorf("managed config %s exceeds %d bytes", path, windowsEnterpriseConfigProfileLimit)
	}
	var document struct {
		Enterprise struct {
			Profile string `yaml:"profile"`
			Trust   struct {
				Mode           string   `yaml:"mode"`
				AllowedSigners []string `yaml:"allowed_signers"`
			} `yaml:"trust"`
		} `yaml:"enterprise"`
	}
	if err := yaml.Unmarshal(trimWindowsJSONBOM(body), &document); err != nil {
		return windowsEnterpriseConfigProfile{}, fmt.Errorf("parse managed config %s: %w", path, err)
	}
	profile := managed.NormalizeEnterpriseProfile(document.Enterprise.Profile)
	if profile != "" && profile != managed.ProfileSecureClient && profile != managed.ProfileStandalone {
		return windowsEnterpriseConfigProfile{}, windowsEnterpriseInvalidArguments("enterprise.profile %q in %s is not %s or %s", document.Enterprise.Profile, path, managed.ProfileSecureClient, managed.ProfileStandalone)
	}
	return windowsEnterpriseConfigProfile{
		profile:        profile,
		trustMode:      strings.ToLower(strings.TrimSpace(document.Enterprise.Trust.Mode)),
		allowedSigners: document.Enterprise.Trust.AllowedSigners,
	}, nil
}

// applyWindowsEnterpriseConfigTrust applies enterprise.trust from the
// supplied --config to the standalone payload trust: a flag and the config
// may agree, the config fills an unset flag, and a disagreement is refused
// rather than silently resolved either way.
func applyWindowsEnterpriseConfigTrust(opts *windowsEnterpriseLifecycleOptions) error {
	path := strings.TrimSpace(opts.configPath)
	if configured := opts.configTrustMode; configured != "" {
		requested := strings.ToLower(strings.TrimSpace(opts.trustMode))
		if requested != "" && requested != configured {
			return windowsEnterpriseInvalidArguments("--trust-mode %s conflicts with enterprise.trust.mode %s in %s%s",
				requested, configured, path, windowsEnterpriseTrustConflictHint(requested, configured))
		}
		opts.trustMode = configured
	}
	if len(opts.configAllowedSigners) == 0 {
		return nil
	}
	normalize := func(values []string) []string {
		set := map[string]bool{}
		for _, value := range values {
			if value = strings.ToLower(strings.TrimSpace(value)); value != "" {
				set[value] = true
			}
		}
		out := make([]string, 0, len(set))
		for value := range set {
			out = append(out, value)
		}
		sort.Strings(out)
		return out
	}
	configured := normalize(opts.configAllowedSigners)
	if len(opts.allowedSigners) != 0 {
		if strings.Join(normalize(opts.allowedSigners), ",") != strings.Join(configured, ",") {
			return windowsEnterpriseInvalidArguments("--allowed-signer conflicts with enterprise.trust.allowed_signers in %s", path)
		}
		return nil
	}
	opts.allowedSigners = configured
	return nil
}

// windowsEnterpriseTrustConflictHint tells the administrator how to resolve
// a --trust-mode that disagrees with enterprise.trust.mode. The unsigned
// standalone Setup always passes --trust-mode hash_pinned, so a config that
// requires authenticode cannot install its payload.
func windowsEnterpriseTrustConflictHint(requested, configured string) string {
	switch {
	case requested == windowsEnterpriseTrustHashPinned && configured == windowsEnterpriseTrustAuthenticode:
		return "; this run installs an unsigned, hash-pinned payload (as the unsigned Setup does), which the config's authenticode requirement refuses: deploy the signed Setup, or set enterprise.trust.mode to hash_pinned or remove it"
	case requested == windowsEnterpriseTrustAuthenticode && configured == windowsEnterpriseTrustHashPinned:
		return "; the config requires a hash-pinned payload: pass --trust-mode hash_pinned with --payload-manifest (as the unsigned Setup does), or remove enterprise.trust.mode"
	}
	return ""
}

// windowsEnterpriseStandalonePowerShellArgs are the installer arguments only
// the standalone profile carries; Secure Client arguments are unchanged.
func windowsEnterpriseStandalonePowerShellArgs(opts *windowsEnterpriseLifecycleOptions) []string {
	if !windowsEnterpriseStandalone(opts) {
		return nil
	}
	args := []string{"-EnterpriseProfile", "Standalone"}
	if opts.trustMode == windowsEnterpriseTrustHashPinned {
		args = append(args, "-TrustMode", "HashPinned", "-PayloadManifest", opts.payloadManifest)
	} else {
		args = append(args, "-TrustMode", "Authenticode")
	}
	if len(opts.allowedSigners) != 0 {
		args = append(args, "-AllowedSigners", strings.Join(opts.allowedSigners, ","))
	}
	if version := strings.TrimSpace(opts.productVersion); version != "" {
		args = append(args, "-ProductVersion", version)
	}
	return args
}

// loadWindowsEnterprisePayloadManifest reads the hash-pinned trust anchor:
// {"schema_version":1,"files":{"<leaf>":"<sha256>"}}. It must be an
// administrator-owned file, like the managed config it accompanies.
func loadWindowsEnterprisePayloadManifest(path string) (map[string]string, error) {
	clean, err := filepath.Abs(strings.TrimSpace(path))
	if err != nil {
		return nil, fmt.Errorf("resolve payload manifest: %w", err)
	}
	info, err := os.Lstat(clean)
	if err != nil {
		return nil, fmt.Errorf("inspect payload manifest: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("payload manifest is not a regular non-link file: %s", clean)
	}
	if err := managed.ValidateTrustedFilePath(clean, "payload SHA-256 manifest"); err != nil {
		return nil, fmt.Errorf("refusing untrusted payload manifest: %w", err)
	}
	file, err := os.Open(clean)
	if err != nil {
		return nil, fmt.Errorf("open payload manifest: %w", err)
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, windowsEnterprisePayloadManifestLimit+1))
	if err != nil {
		return nil, fmt.Errorf("read payload manifest: %w", err)
	}
	if len(body) > windowsEnterprisePayloadManifestLimit {
		return nil, fmt.Errorf("payload manifest exceeds %d bytes", windowsEnterprisePayloadManifestLimit)
	}
	return parseWindowsEnterprisePayloadManifest(body)
}

func parseWindowsEnterprisePayloadManifest(body []byte) (map[string]string, error) {
	var document struct {
		SchemaVersion int               `json:"schema_version"`
		Files         map[string]string `json:"files"`
	}
	decoder := json.NewDecoder(bytes.NewReader(trimWindowsJSONBOM(body)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return nil, fmt.Errorf("parse payload manifest: %w", err)
	}
	if document.SchemaVersion != 1 || len(document.Files) == 0 {
		return nil, errors.New("payload manifest must be schema_version 1 with a non-empty files map")
	}
	pins := make(map[string]string, len(document.Files))
	for name, digest := range document.Files {
		digest = strings.ToLower(strings.TrimSpace(digest))
		if !windowsEnterprisePayloadLeafPattern.MatchString(name) || !windowsEnterpriseSHA256Pattern.MatchString(digest) {
			return nil, fmt.Errorf("payload manifest has an invalid entry %q", name)
		}
		pins[strings.ToLower(name)] = digest
	}
	return pins, nil
}

// verifyWindowsEnterpriseHashPinnedInstaller admits an unsigned installer
// and module only when both digests are pinned. PowerShell 7 cannot verify
// the script it is about to run, so the CLI does it before launching.
func verifyWindowsEnterpriseHashPinnedInstaller(script, manifestPath string) error {
	pins, err := loadWindowsEnterprisePayloadManifest(manifestPath)
	if err != nil {
		return err
	}
	for _, path := range []string{script, filepath.Join(filepath.Dir(script), "DefenseClawEnterprise.psm1")} {
		want, ok := pins[strings.ToLower(filepath.Base(path))]
		if !ok {
			return fmt.Errorf("payload manifest does not pin %s", filepath.Base(path))
		}
		got, err := windowsEnterpriseFileSHA256(path)
		if err != nil {
			return err
		}
		if got != want {
			return fmt.Errorf("%s SHA-256 %s does not match the payload manifest", filepath.Base(path), got)
		}
	}
	return nil
}

func windowsEnterpriseFileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("open %s for hashing: %w", path, err)
	}
	defer file.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
