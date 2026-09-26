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
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/sys/windows"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// The standalone profile wraps the installer's schema-1 document in the
// cross-platform enterprisestatus schema-2 result, registers the deployment
// for MDM detection, and records every run in the event log and a rotated
// lifecycle log. None of this runs for the Secure Client profile.

// windowsEnterpriseStandaloneRun is one installer run on PowerShell 7.
type windowsEnterpriseStandaloneRun struct {
	Output    []byte
	Truncated bool
	ExitCode  int
}

// windowsEnterpriseInstallerReport is the subset of the installer's schema-1
// status document the standalone result is built from.
type windowsEnterpriseInstallerReport struct {
	SchemaVersion                     int      `json:"schema_version"`
	OK                                bool     `json:"ok"`
	Action                            string   `json:"action"`
	Installed                         bool     `json:"installed"`
	TransactionPending                bool     `json:"transaction_pending"`
	InstallRoot                       string   `json:"install_root"`
	StateRoot                         string   `json:"state_root"`
	GatewayService                    string   `json:"gateway_service"`
	GuardianService                   string   `json:"guardian_service"`
	GatewayServiceState               string   `json:"gateway_service_state"`
	GuardianServiceState              string   `json:"guardian_service_state"`
	SensorHelperService               string   `json:"sensor_helper_service"`
	SensorHelperServiceState          string   `json:"sensor_helper_service_state"`
	EnumeratorService                 string   `json:"enumerator_service"`
	EnumeratorServiceState            string   `json:"enumerator_service_state"`
	GatewayReady                      bool     `json:"gateway_ready"`
	GuardianReady                     bool     `json:"guardian_ready"`
	CodexMachineRequirementsReady     bool     `json:"codex_machine_requirements_ready"`
	CodexMachineRequirementsDisposion string   `json:"codex_machine_requirements_disposition"`
	CodexTargetEnabled                bool     `json:"codex_target_enabled"`
	CursorTargetEnabled               bool     `json:"cursor_target_enabled"`
	ClaudeTargetEnabled               bool     `json:"claude_target_enabled"`
	ClaudeEffectivePolicyVerified     bool     `json:"claude_effective_policy_verified"`
	SecurityComplete                  bool     `json:"security_complete"`
	InstalledVersion                  string   `json:"installed_version"`
	TrustMode                         string   `json:"trust_mode"`
	Error                             string   `json:"error"`
	Errors                            []string `json:"errors"`
}

var (
	windowsEnterpriseStandaloneRunner = runWindowsEnterprisePowerShell7
	// windowsEnterpriseStandaloneObserver records a finished standalone
	// result (registration, event log, lifecycle log). Tests replace it.
	windowsEnterpriseStandaloneObserver = observeWindowsEnterpriseStandaloneResult
	// windowsEnterpriseStandaloneFootprint reports whether any standalone
	// deployment state or service exists; uninstall on a clean host is a
	// no-op.
	windowsEnterpriseStandaloneFootprint = windowsEnterpriseStandaloneFootprintPresent
	windowsEnterpriseEnsureDriftDetector = windowsEnterpriseEnsureDrift

	windowsEnterpriseMessageCodePattern = regexp.MustCompile(`^([a-z][a-z0-9_]{2,63}):\s`)
)

// windowsEnterpriseLifecycleBusyMarker is the installer's lock-contention
// diagnostic (Enter-DefenseClawLifecycleLock).
const windowsEnterpriseLifecycleBusyMarker = "holds the protected file lock"

func windowsEnterpriseStandaloneRequested(opts *windowsEnterpriseLifecycleOptions) bool {
	return opts != nil && (windowsEnterpriseStandalone(opts) ||
		managed.IsStandaloneProfile(opts.profile))
}

// runWindowsEnterprisePowerShell7 runs the installer on the validated
// PowerShell 7 engine and captures its schema-1 JSON document.
func runWindowsEnterprisePowerShell7(
	ctx context.Context,
	cmd *cobra.Command,
	script string,
	args []string,
) (windowsEnterpriseStandaloneRun, error) {
	engine, err := windowsEnterprisePowerShell7Finder()
	if err != nil {
		return windowsEnterpriseStandaloneRun{}, err
	}
	environment := func(temp string) ([]string, error) {
		return trustedWindowsEnterprisePowerShell7Environment(temp, engine)
	}
	stderr := &windowsEnterpriseOutputCapture{}
	capture, runErr := runWindowsEnterprisePowerShellEngine(
		ctx, cmd, engine.Executable, environment, script, args,
		io.Discard, io.MultiWriter(cmd.ErrOrStderr(), stderr),
	)
	run := windowsEnterpriseStandaloneRun{}
	if capture != nil {
		run.Output = append([]byte(nil), capture.buffer.Bytes()...)
		run.Truncated = capture.truncated
	}
	if runErr != nil {
		// A nonzero installer exit that still produced its JSON document is
		// a reported failure, not a launch failure.
		if code, ok := windowsEnterpriseInstallerExitCode(runErr); ok && len(bytes.TrimSpace(run.Output)) != 0 {
			run.ExitCode = code
			return run, nil
		}
		// A refusal before the installer could emit JSON (engine, bitness,
		// language mode) names its stable code on stderr; keep it.
		if detail := windowsEnterpriseStderrCode(stderr.buffer.Bytes()); detail != "" {
			return run, fmt.Errorf("%s (%w)", detail, runErr)
		}
		return run, runErr
	}
	return run, nil
}

// windowsEnterpriseStderrCode returns the first stderr line that carries a
// stable refusal code.
func windowsEnterpriseStderrCode(body []byte) string {
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		for _, code := range windowsEnterpriseKnownCodes {
			if index := strings.Index(line, code+":"); index >= 0 {
				detail := line[index:]
				if len(detail) > windowsEnterpriseDiagnosticMax {
					detail = detail[:windowsEnterpriseDiagnosticMax]
				}
				return detail
			}
		}
	}
	return ""
}

var windowsEnterpriseInstallerExitPattern = regexp.MustCompile(`\(exit code (-?[0-9]+)\)|exited with code (-?[0-9]+)`)

func windowsEnterpriseInstallerExitCode(err error) (int, bool) {
	match := windowsEnterpriseInstallerExitPattern.FindStringSubmatch(err.Error())
	if match == nil {
		return 0, false
	}
	value := match[1]
	if value == "" {
		value = match[2]
	}
	code, parseErr := strconv.Atoi(value)
	return code, parseErr == nil
}

// runWindowsEnterpriseStandaloneAction runs one explicit lifecycle action
// and reports it as a schema-2 result.
func runWindowsEnterpriseStandaloneAction(
	ctx context.Context,
	cmd *cobra.Command,
	action string,
	opts *windowsEnterpriseLifecycleOptions,
	script string,
	args []string,
) error {
	if action == "uninstall" {
		present, err := windowsEnterpriseStandaloneFootprint()
		if err == nil && !present {
			result := newWindowsEnterpriseStandaloneResult(action, opts)
			result.Noop = true
			result.NoopReason = "not_installed"
			return finishWindowsEnterpriseStandalone(cmd, opts, result, 0)
		}
	}
	report, run, err := runWindowsEnterpriseStandaloneInstaller(ctx, cmd, opts, script, args)
	result := newWindowsEnterpriseStandaloneResult(action, opts)
	if err != nil {
		result.AddError(windowsEnterpriseMessageCode(err.Error(), "lifecycle_launch_failed"), err.Error())
		return finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
	}
	if action == "uninstall" && windowsEnterpriseRecoveredFailedInstall(report) {
		// Uninstall rolled back a failed first install. The host is at the
		// requested end state, so an MDM must see success, not a retryable
		// failure that would loop forever.
		if present, err := windowsEnterpriseStandaloneFootprint(); err == nil && !present {
			result.Noop = true
			result.NoopReason = "recovered_failed_install"
			result.AddWarning("recovered_failed_install", "uninstall rolled back a failed initial install; nothing remains installed")
			return finishWindowsEnterpriseStandalone(cmd, opts, result, 0)
		}
	}
	applyWindowsEnterpriseInstallerReport(result, report, run)
	return finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
}

// windowsEnterpriseRecoveredFailedInstall reports whether the lifecycle
// stopped only because it rolled back a failed initial install, which leaves
// the host without a deployment rather than broken.
func windowsEnterpriseRecoveredFailedInstall(report *windowsEnterpriseInstallerReport) bool {
	if report == nil || report.OK || report.Installed || report.TransactionPending {
		return false
	}
	messages := append([]string{}, report.Errors...)
	if strings.TrimSpace(report.Error) != "" {
		messages = append(messages, report.Error)
	}
	if len(messages) == 0 {
		return false
	}
	for _, message := range messages {
		if !strings.Contains(message, "recovered a failed initial install") {
			return false
		}
	}
	return true
}

func runWindowsEnterpriseStandaloneInstaller(
	ctx context.Context,
	cmd *cobra.Command,
	opts *windowsEnterpriseLifecycleOptions,
	script string,
	args []string,
) (*windowsEnterpriseInstallerReport, windowsEnterpriseStandaloneRun, error) {
	if !containsString(args, "-Json") {
		args = append(append([]string{}, args...), "-Json")
	}
	run, err := windowsEnterpriseStandaloneRunner(ctx, cmd, script, args)
	if err != nil {
		return nil, run, err
	}
	if run.Truncated {
		return nil, run, errors.New("the installer's JSON report exceeded the capture limit")
	}
	report, parseErr := parseWindowsEnterpriseInstallerReport(run.Output)
	if parseErr != nil {
		return nil, run, fmt.Errorf("installer exited %d without a valid JSON report: %w", run.ExitCode, parseErr)
	}
	return report, run, nil
}

// parseWindowsEnterpriseInstallerReport takes the last JSON object line;
// PowerShell may emit warnings or host output before the document.
func parseWindowsEnterpriseInstallerReport(body []byte) (*windowsEnterpriseInstallerReport, error) {
	lines := bytes.Split(trimWindowsJSONBOM(bytes.TrimSpace(body)), []byte("\n"))
	for index := len(lines) - 1; index >= 0; index-- {
		line := bytes.TrimSpace(trimWindowsJSONBOM(lines[index]))
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var report windowsEnterpriseInstallerReport
		if err := json.Unmarshal(line, &report); err != nil {
			continue
		}
		if report.SchemaVersion != 1 {
			return nil, fmt.Errorf("installer report schema_version %d is not 1", report.SchemaVersion)
		}
		return &report, nil
	}
	return nil, errors.New("no JSON object in installer output")
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func newWindowsEnterpriseStandaloneResult(action string, opts *windowsEnterpriseLifecycleOptions) *enterprisestatus.Result {
	version := strings.TrimSpace(opts.productVersion)
	if version == "" {
		version = strings.TrimSpace(appVersion)
	}
	result := enterprisestatus.New(action, managed.ProfileStandalone, "windows", version)
	result.Inspection = enterprisestatus.Inspection{Local: "active", AIDefense: "disabled"}
	return result
}

func applyWindowsEnterpriseInstallerReport(
	result *enterprisestatus.Result,
	report *windowsEnterpriseInstallerReport,
	run windowsEnterpriseStandaloneRun,
) {
	result.Installed = report.Installed
	result.TransactionPending = report.TransactionPending
	result.InstalledVersion = report.InstalledVersion
	for _, service := range []struct {
		name, state, kind string
	}{
		{report.GatewayService, report.GatewayServiceState, "gateway"},
		{report.GuardianService, report.GuardianServiceState, "guardian"},
		{report.EnumeratorService, report.EnumeratorServiceState, "enumerator"},
		{report.SensorHelperService, report.SensorHelperServiceState, "sensor_helper"},
	} {
		if strings.TrimSpace(service.name) == "" {
			continue
		}
		result.Services = append(result.Services, enterprisestatus.Service{
			Name:     service.name,
			Kind:     service.kind,
			State:    service.state,
			Required: true,
		})
	}
	result.Readiness = enterprisestatus.Readiness{
		Gateway:      report.GatewayReady,
		Guardian:     report.GuardianReady,
		Enumerator:   report.EnumeratorServiceState == "running",
		SensorHelper: report.SensorHelperServiceState == "running",
	}
	if report.CodexTargetEnabled {
		result.MachinePolicy["codex"] = windowsEnterpriseMachinePolicy(report.CodexMachineRequirementsReady)
	}
	if report.ClaudeTargetEnabled {
		result.MachinePolicy["claudecode"] = windowsEnterpriseMachinePolicy(report.ClaudeEffectivePolicyVerified)
	}
	if report.CursorTargetEnabled {
		result.MachinePolicy["cursor"] = windowsEnterpriseMachinePolicy(report.GuardianReady)
	}
	result.CoverageComplete = report.Installed && report.GuardianReady && !report.TransactionPending
	result.SecurityComplete = report.SecurityComplete
	if report.Installed {
		enrollment, err := readWindowsEnterpriseStandaloneEnrollment()
		if err == nil {
			result.Enrollment = enrollment
		}
		aiDefense, err := readWindowsEnterpriseStandaloneAIDefense()
		if err == nil && aiDefense {
			result.Inspection.AIDefense = "unavailable:gateway_not_ready"
			if report.GatewayReady {
				result.Inspection.AIDefense = "ok"
			}
		}
	}
	messages := append([]string{}, report.Errors...)
	if len(messages) == 0 && strings.TrimSpace(report.Error) != "" {
		messages = append(messages, report.Error)
	}
	for _, message := range messages {
		message = strings.TrimSpace(message)
		if message == "" {
			continue
		}
		result.AddError(windowsEnterpriseMessageCode(message, "lifecycle_error"), message)
	}
	if !report.OK && len(result.Errors) == 0 {
		code := "not_ready"
		if !report.Installed {
			code = "not_installed"
		}
		result.AddError(code, fmt.Sprintf("the standalone deployment is not healthy (installer exit %d)", run.ExitCode))
	}
}

func windowsEnterpriseMachinePolicy(verified bool) enterprisestatus.MachinePolicyState {
	state := enterprisestatus.MachinePolicyState{Ownership: "merge", Lock: "enforce"}
	if verified {
		state.EffectiveLock = "enforce"
	}
	return state
}

// windowsEnterpriseMessageCode extracts a leading stable code
// ("powershell7_required: ...") or classifies well-known diagnostics.
func windowsEnterpriseMessageCode(message, fallback string) string {
	if strings.Contains(message, windowsEnterpriseLifecycleBusyMarker) {
		return "lifecycle_busy"
	}
	if strings.HasPrefix(message, errWindowsEnterpriseInvalidArguments.Error()+": ") {
		return "invalid_arguments"
	}
	if match := windowsEnterpriseMessageCodePattern.FindStringSubmatch(message); match != nil {
		return match[1]
	}
	for _, known := range windowsEnterpriseKnownCodes {
		if strings.Contains(message, known) {
			return known
		}
	}
	return fallback
}

// windowsEnterpriseKnownCodes are the stable refusal codes the standalone
// installer and module emit.
var windowsEnterpriseKnownCodes = []string{
	"powershell7_required",
	"powershell7_untrusted",
	"powershell_32bit_host",
	"powershell_constrained_language",
	"unsupported_architecture",
	"profile_conflict",
	"downgrade_refused",
}

func windowsEnterpriseFailureCodeFor(result *enterprisestatus.Result) int {
	for _, message := range result.Errors {
		switch message.Code {
		case "lifecycle_busy":
			return enterprisestatus.WindowsExitBusy
		case "invalid_arguments":
			return enterprisestatus.WindowsExitInvalidArgs
		}
	}
	return enterprisestatus.WindowsExitFailure
}

// finishWindowsEnterpriseStandalone records and prints a result and turns
// it into the process exit code.
func finishWindowsEnterpriseStandalone(
	cmd *cobra.Command,
	opts *windowsEnterpriseLifecycleOptions,
	result *enterprisestatus.Result,
	failureCode int,
) error {
	exitCode := result.Finish("windows", failureCode)
	result.LogPath = windowsEnterpriseStandaloneObserver(result, opts)
	if opts.jsonOutput {
		if err := json.NewEncoder(cmd.OutOrStdout()).Encode(result); err != nil {
			return withExitCode(fmt.Errorf("encode the standalone lifecycle result: %w", err), enterprisestatus.WindowsExitFailure)
		}
	} else {
		writeWindowsEnterpriseStandaloneSummary(cmd.OutOrStdout(), result)
	}
	if exitCode == 0 {
		return nil
	}
	summary := "the standalone enterprise " + result.Action + " failed"
	if len(result.Errors) != 0 {
		summary += ": " + result.Errors[0].Message
	}
	return withExitCode(errors.New(summary), exitCode)
}

func writeWindowsEnterpriseStandaloneSummary(output io.Writer, result *enterprisestatus.Result) {
	state := "OK"
	if !result.OK {
		state = "FAILED"
	}
	fmt.Fprintf(output, "DefenseClaw Windows enterprise %s (standalone): %s\n", result.Action, state)
	if result.Noop {
		fmt.Fprintf(output, "  No change: %s\n", result.NoopReason)
	}
	if result.InstalledVersion != "" {
		fmt.Fprintf(output, "  Installed version: %s\n", result.InstalledVersion)
	}
	for _, service := range result.Services {
		fmt.Fprintf(output, "  %s (%s): %s\n", service.Name, service.Kind, service.State)
	}
	for _, message := range result.Errors {
		fmt.Fprintf(output, "  error %s: %s\n", message.Code, message.Message)
	}
	if result.LogPath != "" {
		fmt.Fprintf(output, "  Log: %s\n", result.LogPath)
	}
}

func writeWindowsEnterpriseStandalonePreflightFailure(
	cmd *cobra.Command,
	action string,
	opts *windowsEnterpriseLifecycleOptions,
	cause error,
) error {
	if cause == nil {
		return nil
	}
	if opts == nil {
		opts = &windowsEnterpriseLifecycleOptions{}
	}
	result := newWindowsEnterpriseStandaloneResult(action, opts)
	code := "preflight_failed"
	if errors.Is(cause, errWindowsEnterpriseInvalidArguments) {
		code = "invalid_arguments"
	} else {
		code = windowsEnterpriseMessageCode(cause.Error(), code)
	}
	if errors.Is(cause, errPowerShell7Required) {
		code = "powershell7_required"
	}
	if errors.Is(cause, errPowerShell7Untrusted) {
		code = "powershell7_untrusted"
	}
	result.AddError(code, cause.Error())
	return finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
}

// windowsEnterpriseStandaloneFootprintPresent reports any standalone
// metadata, root, or managed service. Only a host with none of them makes
// uninstall a no-op; anything else goes through the authenticated
// uninstall and exact-scope recovery.
func windowsEnterpriseStandaloneFootprintPresent() (bool, error) {
	roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
	if err != nil {
		return false, err
	}
	for _, path := range []string{roots.MetadataPath, roots.InstallRoot, roots.StateRoot} {
		if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
	}
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return true, nil
	}
	defer windows.CloseServiceHandle(manager)
	for _, name := range []string{"DefenseClawGateway", "DefenseClawHookGuardian", "DefenseClawHookEnumerator", "DefenseClawSensorHelper"} {
		namePointer, err := windows.UTF16PtrFromString(name)
		if err != nil {
			return true, nil
		}
		service, err := windows.OpenService(manager, namePointer, windows.SERVICE_QUERY_STATUS)
		if err == nil {
			_ = windows.CloseServiceHandle(service)
			return true, nil
		}
		if !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return true, nil
		}
	}
	return false, nil
}

// readWindowsEnterpriseStandaloneEnrollment summarizes the installed
// guardian manifest when this token can read it.
func readWindowsEnterpriseStandaloneEnrollment() (enterprisestatus.Enrollment, error) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return enterprisestatus.Enrollment{}, err
	}
	body, err := readWindowsEnterpriseBoundedFile(layout.ManifestPath, 16<<20)
	if err != nil {
		return enterprisestatus.Enrollment{}, err
	}
	var manifest struct {
		Targets []struct {
			Enabled  bool `yaml:"enabled"`
			Deferred bool `yaml:"deferred"`
		} `yaml:"targets"`
	}
	if err := yaml.Unmarshal(body, &manifest); err != nil {
		return enterprisestatus.Enrollment{}, err
	}
	enrollment := enterprisestatus.Enrollment{Targets: len(manifest.Targets)}
	for _, target := range manifest.Targets {
		if target.Deferred {
			enrollment.Pending++
		}
		if !target.Enabled {
			enrollment.Exempt++
		}
	}
	return enrollment, nil
}

// readWindowsEnterpriseStandaloneAIDefense reports whether the installed
// config enables the optional AI Defense augmentation.
func readWindowsEnterpriseStandaloneAIDefense() (bool, error) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return false, err
	}
	body, err := readWindowsEnterpriseBoundedFile(layout.ConfigPath, windowsEnterpriseConfigProfileLimit)
	if err != nil {
		return false, err
	}
	var document struct {
		Enterprise struct {
			Inspection struct {
				AIDefense struct {
					Enabled bool `yaml:"enabled"`
				} `yaml:"ai_defense"`
			} `yaml:"inspection"`
		} `yaml:"enterprise"`
	}
	if err := yaml.Unmarshal(body, &document); err != nil {
		return false, err
	}
	return document.Enterprise.Inspection.AIDefense.Enabled, nil
}

func readWindowsEnterpriseBoundedFile(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, limit)
	}
	return body, nil
}

// ensure ------------------------------------------------------------------

// windowsEnterpriseEnsurePlan is the action ensure selected and why.
type windowsEnterpriseEnsurePlan struct {
	Action string // "", install, upgrade, repair
	Reason string
}

// runWindowsEnterpriseStandaloneEnsure converges the host to the supplied
// payload and config: a pending transaction is repaired, an absent
// deployment is installed, an older one upgraded, drifted binaries or
// config reapplied, a failed verify repaired, and a compliant deployment
// left untouched.
func runWindowsEnterpriseStandaloneEnsure(
	ctx context.Context,
	cmd *cobra.Command,
	opts *windowsEnterpriseLifecycleOptions,
	script string,
) error {
	defaultWindowsEnterpriseEnsurePayload(opts, script)
	statusOpts := *opts
	statusOpts.jsonOutput = true
	statusReport, statusRun, err := runWindowsEnterpriseStandaloneInstaller(ctx, cmd, opts, script, windowsEnterprisePowerShellArgs("status", &statusOpts))
	result := newWindowsEnterpriseStandaloneResult("ensure", opts)
	if err != nil {
		result.AddError(windowsEnterpriseMessageCode(err.Error(), "lifecycle_launch_failed"), err.Error())
		return finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
	}
	plan, planErr := planWindowsEnterpriseEnsure(statusReport, opts, script)
	if planErr != nil {
		applyWindowsEnterpriseInstallerReport(result, statusReport, statusRun)
		result.Errors = []enterprisestatus.Message{}
		result.AddError(windowsEnterpriseMessageCode(planErr.Error(), "ensure_refused"), planErr.Error())
		return finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
	}
	if plan.Action == "" {
		verifyOpts := *opts
		verifyOpts.jsonOutput = true
		verifyReport, verifyRun, err := runWindowsEnterpriseStandaloneInstaller(ctx, cmd, opts, script, windowsEnterprisePowerShellArgs("verify", &verifyOpts))
		if err != nil {
			result.AddError(windowsEnterpriseMessageCode(err.Error(), "lifecycle_launch_failed"), err.Error())
			return finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
		}
		if verifyReport.OK {
			applyWindowsEnterpriseInstallerReport(result, verifyReport, verifyRun)
			result.Noop = true
			result.NoopReason = plan.Reason
			return finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
		}
		plan = windowsEnterpriseEnsurePlan{Action: "repair", Reason: "verify_failed"}
	}

	actionOpts := *opts
	actionOpts.jsonOutput = true
	if plan.Action == "repair" {
		// Repair reapplies ACL, service, and environment invariants from the
		// installed payload; it takes no sources.
		clearWindowsEnterpriseSources(&actionOpts)
	}
	var cleanupManifest func()
	if plan.Action == "install" && strings.TrimSpace(actionOpts.manifestPath) == "" && strings.TrimSpace(actionOpts.mode) == "" {
		manifestPath, cleanup, err := stageWindowsEnterpriseEnsureManifest(ctx, cmd, actionOpts.configPath)
		if err != nil {
			result.AddError("manifest_staging_failed", err.Error())
			return finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
		}
		cleanupManifest = cleanup
		actionOpts.manifestPath = manifestPath
	}
	if cleanupManifest != nil {
		defer cleanupManifest()
	}
	report, run, err := runWindowsEnterpriseStandaloneInstaller(ctx, cmd, opts, script, windowsEnterprisePowerShellArgs(plan.Action, &actionOpts))
	if err != nil {
		result.AddError(windowsEnterpriseMessageCode(err.Error(), "lifecycle_launch_failed"), err.Error())
		return finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
	}
	if plan.Action == "repair" && plan.Reason == "transaction_pending" && windowsEnterpriseRecoveredFailedInstall(report) {
		// The pending transaction was a failed first install; repair rolled it
		// back to an empty host. Converge by installing, exactly as ensure
		// does on a clean device.
		result.AddWarning("recovered_failed_install", "ensure rolled back a failed initial install before installing")
		installPlan, planErr := planWindowsEnterpriseEnsure(&windowsEnterpriseInstallerReport{}, opts, script)
		if planErr != nil {
			result.AddError(windowsEnterpriseMessageCode(planErr.Error(), "ensure_refused"), planErr.Error())
			return finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
		}
		plan = installPlan
		actionOpts = *opts
		actionOpts.jsonOutput = true
		if strings.TrimSpace(actionOpts.manifestPath) == "" && strings.TrimSpace(actionOpts.mode) == "" {
			manifestPath, cleanup, err := stageWindowsEnterpriseEnsureManifest(ctx, cmd, actionOpts.configPath)
			if err != nil {
				result.AddError("manifest_staging_failed", err.Error())
				return finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
			}
			defer cleanup()
			actionOpts.manifestPath = manifestPath
		}
		report, run, err = runWindowsEnterpriseStandaloneInstaller(ctx, cmd, opts, script, windowsEnterprisePowerShellArgs(plan.Action, &actionOpts))
		if err != nil {
			result.AddError(windowsEnterpriseMessageCode(err.Error(), "lifecycle_launch_failed"), err.Error())
			return finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
		}
	}
	applyWindowsEnterpriseInstallerReport(result, report, run)
	result.AddWarning("ensure_"+plan.Action, "ensure ran "+plan.Action+": "+plan.Reason)
	return finishWindowsEnterpriseStandalone(cmd, opts, result, windowsEnterpriseFailureCodeFor(result))
}

// planWindowsEnterpriseEnsure chooses the converging action from the
// current status. An empty action means "verify, then no-op or repair".
func planWindowsEnterpriseEnsure(
	status *windowsEnterpriseInstallerReport,
	opts *windowsEnterpriseLifecycleOptions,
	script string,
) (windowsEnterpriseEnsurePlan, error) {
	if status.TransactionPending {
		return windowsEnterpriseEnsurePlan{Action: "repair", Reason: "transaction_pending"}, nil
	}
	if !status.Installed {
		if strings.TrimSpace(opts.configPath) == "" && strings.TrimSpace(opts.mode) == "" {
			return windowsEnterpriseEnsurePlan{}, windowsEnterpriseInvalidArguments("ensure must install and requires --config (or --mode/--connector)")
		}
		if missing := missingWindowsEnterpriseSources(opts); len(missing) != 0 {
			return windowsEnterpriseEnsurePlan{}, windowsEnterpriseInvalidArguments("ensure must install and requires %s", strings.Join(missing, ", "))
		}
		return windowsEnterpriseEnsurePlan{Action: "install", Reason: "not_installed"}, nil
	}
	switch compareWindowsEnterpriseVersions(opts.productVersion, status.InstalledVersion) {
	case 1:
		if missing := missingWindowsEnterpriseSources(opts); len(missing) != 0 {
			return windowsEnterpriseEnsurePlan{}, windowsEnterpriseInvalidArguments("ensure must upgrade and requires %s", strings.Join(missing, ", "))
		}
		return windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "older_version:" + status.InstalledVersion}, nil
	case -1:
		return windowsEnterpriseEnsurePlan{}, fmt.Errorf("downgrade_refused: installed version %s is newer than %s; run upgrade explicitly to downgrade", status.InstalledVersion, opts.productVersion)
	}
	drift, err := windowsEnterpriseEnsureDriftDetector(opts, script)
	if err != nil {
		return windowsEnterpriseEnsurePlan{}, err
	}
	if drift != "" {
		if missing := missingWindowsEnterpriseSources(opts); len(missing) != 0 {
			return windowsEnterpriseEnsurePlan{}, windowsEnterpriseInvalidArguments("ensure must reapply %s and requires %s", drift, strings.Join(missing, ", "))
		}
		return windowsEnterpriseEnsurePlan{Action: "upgrade", Reason: "drift:" + drift}, nil
	}
	return windowsEnterpriseEnsurePlan{Reason: "compliant"}, nil
}

func missingWindowsEnterpriseSources(opts *windowsEnterpriseLifecycleOptions) []string {
	var missing []string
	for _, source := range []struct{ flag, value string }{
		{"--gateway-binary", opts.gatewayBinary},
		{"--acp-binary", opts.acpBinary},
		{"--hook-binary", opts.hookBinary},
		{"--sensor-helper-binary", opts.sensorHelperBinary},
	} {
		if strings.TrimSpace(source.value) == "" {
			missing = append(missing, source.flag)
		}
	}
	return missing
}

func clearWindowsEnterpriseSources(opts *windowsEnterpriseLifecycleOptions) {
	opts.gatewayBinary, opts.acpBinary, opts.hookBinary = "", "", ""
	opts.sensorHelperBinary, opts.cliBinary = "", ""
	opts.configPath, opts.manifestPath, opts.mode, opts.connector = "", "", "", ""
}

// defaultWindowsEnterpriseEnsurePayload fills unset binary sources from the
// installer's own directory, which is how the enterprise Setup and an
// extracted MDM package lay out the payload.
func defaultWindowsEnterpriseEnsurePayload(opts *windowsEnterpriseLifecycleOptions, script string) {
	directory := filepath.Dir(script)
	for _, source := range []struct {
		value *string
		name  string
	}{
		{&opts.gatewayBinary, "defenseclaw-gateway.exe"},
		{&opts.acpBinary, "defenseclaw-acp.exe"},
		{&opts.hookBinary, "defenseclaw-hook.exe"},
		{&opts.sensorHelperBinary, "defenseclaw-sensor-helper.exe"},
		{&opts.cliBinary, "defenseclaw.exe"},
	} {
		if strings.TrimSpace(*source.value) != "" {
			continue
		}
		candidate := filepath.Join(directory, source.name)
		if info, err := os.Lstat(candidate); err == nil && info.Mode().IsRegular() {
			*source.value = candidate
		}
	}
	// The running image can never replace itself: a CLI launched from the
	// installed bin directory leaves the installed CLI in place.
	if executable, err := windowsEnterpriseExecutableResolver(); err == nil && opts.cliBinary != "" {
		if conflict, err := windowsEnterpriseSelfUpgradeConflict("upgrade", opts.installRoot, executable, opts.cliBinary); err != nil || conflict {
			opts.cliBinary = ""
		}
	}
}

// windowsEnterpriseEnsureDrift compares the supplied sources with the
// installed deployment's recorded digests and config.
func windowsEnterpriseEnsureDrift(opts *windowsEnterpriseLifecycleOptions, script string) (string, error) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return "", err
	}
	roots, err := winpath.TrustedEnterpriseRoots(managed.ProfileStandalone)
	if err != nil {
		return "", err
	}
	body, err := readWindowsEnterpriseBoundedFile(roots.MetadataPath, 1<<20)
	if err != nil {
		return "", fmt.Errorf("read standalone deployment metadata: %w", err)
	}
	var metadata struct {
		Hashes map[string]string `json:"hashes"`
	}
	if err := json.Unmarshal(trimWindowsJSONBOM(body), &metadata); err != nil {
		return "", fmt.Errorf("parse standalone deployment metadata: %w", err)
	}
	for _, source := range []struct{ key, path string }{
		{"gateway", opts.gatewayBinary},
		{"acp", opts.acpBinary},
		{"hook", opts.hookBinary},
		{"sensor_helper", opts.sensorHelperBinary},
		{"cli", opts.cliBinary},
		{"installer", script},
		{"module", filepath.Join(filepath.Dir(script), "DefenseClawEnterprise.psm1")},
	} {
		if strings.TrimSpace(source.path) == "" {
			continue
		}
		recorded := strings.ToLower(strings.TrimSpace(metadata.Hashes[source.key]))
		if recorded == "" {
			continue
		}
		digest, err := windowsEnterpriseFileSHA256(source.path)
		if err != nil {
			return "", err
		}
		if digest != recorded {
			return source.key, nil
		}
	}
	if path := strings.TrimSpace(opts.configPath); path != "" {
		want, err := windowsEnterpriseFileSHA256(path)
		if err != nil {
			return "", err
		}
		got, err := windowsEnterpriseFileSHA256(layout.ConfigPath)
		if err != nil || got != want {
			return "config", nil
		}
	}
	// An administrator-supplied manifest is drift when the installed
	// guardian manifest no longer carries one of its rows with the same
	// enrollment state (a row edited or removed by hand, or never applied).
	// Rows the enumerator added are not drift.
	if path := strings.TrimSpace(opts.manifestPath); path != "" {
		required, err := enterprisehooks.LoadManifest(path)
		if err != nil {
			return "", fmt.Errorf("read the supplied guardian manifest: %w", err)
		}
		installed, err := enterprisehooks.LoadManifest(layout.ManifestPath)
		if err != nil {
			return "manifest", nil
		}
		if len(windowsEnterpriseManifestUncoveredRows(required.Targets, installed.Targets)) != 0 {
			return "manifest", nil
		}
	}
	return "", nil
}

// compareWindowsEnterpriseVersions orders dotted release versions,
// ignoring a leading "v" and build metadata. A prerelease sorts before its
// release. Unparseable versions compare equal only when identical.
func compareWindowsEnterpriseVersions(left, right string) int {
	left, right = strings.TrimSpace(left), strings.TrimSpace(right)
	if left == right {
		return 0
	}
	l, lPre, lOK := parseWindowsEnterpriseVersion(left)
	r, rPre, rOK := parseWindowsEnterpriseVersion(right)
	if !lOK || !rOK {
		if right == "" {
			return 1
		}
		if left == "" {
			return -1
		}
		// Different unparseable versions (e.g. dev builds): reapply.
		return 1
	}
	if order := compareWindowsVersions(l, r); order != 0 {
		return order
	}
	switch {
	case lPre == rPre:
		return 0
	case lPre == "":
		return 1
	case rPre == "":
		return -1
	case lPre < rPre:
		return -1
	default:
		return 1
	}
}

func parseWindowsEnterpriseVersion(value string) ([]int, string, bool) {
	value = strings.TrimPrefix(strings.TrimPrefix(value, "v"), "V")
	if index := strings.IndexByte(value, '+'); index >= 0 {
		value = value[:index]
	}
	prerelease := ""
	if index := strings.IndexByte(value, '-'); index >= 0 {
		value, prerelease = value[:index], value[index+1:]
	}
	parts := strings.Split(value, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return nil, "", false
	}
	parsed := make([]int, 0, len(parts))
	for _, part := range parts {
		number, err := strconv.Atoi(part)
		if err != nil || number < 0 {
			return nil, "", false
		}
		parsed = append(parsed, number)
	}
	return parsed, prerelease, true
}

// stageWindowsEnterpriseEnsureManifest builds the first guardian manifest
// with the same enumerator the installed service runs, from the supplied
// standalone config, in a protected administrator-only directory.
func stageWindowsEnterpriseEnsureManifest(
	ctx context.Context,
	cmd *cobra.Command,
	configPath string,
) (string, func(), error) {
	if strings.TrimSpace(configPath) == "" {
		return "", nil, errors.New("ensure needs --config to enumerate the first guardian manifest")
	}
	absolute, err := filepath.Abs(configPath)
	if err != nil {
		return "", nil, err
	}
	restore := setTemporaryEnvironment(map[string]string{
		managed.ConfigPathEnv:        absolute,
		managed.DeploymentModeEnv:    managed.DeploymentModeManagedEnterprise,
		managed.EnterpriseProfileEnv: managed.ProfileStandalone,
	})
	cfg, loadErr := config.LoadFromFile(absolute)
	restore()
	if loadErr != nil {
		return "", nil, fmt.Errorf("load the standalone config for enumeration: %w", loadErr)
	}
	programData, err := windowsEnterpriseProgramDataResolver()
	if err != nil {
		return "", nil, err
	}
	directory, err := createProtectedWindowsEnterpriseDirectory(
		programData,
		"DefenseClaw-Ensure-",
		"ensure manifest staging directory",
		rand.Read,
		windows.CreateDirectory,
	)
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	manifest, err := enterpriseWindowsEnumerateProfileEnumerator(ctx, cfg, standaloneWindowsEnumerateOptions(cfg, enterprisehooks.EnumerateOptions{
		Logger: enumerationLoggerForStderr(cmd.ErrOrStderr()),
	}))
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("enumerate local profiles: %w", err)
	}
	path := filepath.Join(directory, "targets.yaml")
	if _, err := enterpriseWindowsEnumerateManifestWriter(path, manifest); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("stage the first guardian manifest: %w", err)
	}
	return path, cleanup, nil
}
