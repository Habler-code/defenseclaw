// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// secureClientSetupGoldenCases is the Secure Client Setup command-line
// surface an AVC or MDM operator reaches: help, every action, the
// deployment-system switches, and each refusal.
var secureClientSetupGoldenCases = [][]string{
	{},
	{"--help"},
	{"/?"},
	{"/install", `CONFIG=C:\staging\config.yaml`, `MANIFEST=C:\staging\targets.yaml`, "/quiet", "/norestart"},
	{"/install", `CONFIG=C:\staging\config.yaml`, `MANIFEST=C:\staging\targets.yaml`, "NOSTART=1", "JSON=true", "TIMEOUTSECONDS=600"},
	{"/install", "--mode=observe", "--connector=codex,claudecode,cursor"},
	{"/install", "--deferred-config"},
	{"/upgrade"},
	{"/repair", "--no-start"},
	{"/reconcile"},
	{"/status", "JSON=1"},
	{"/verify", "--attest-agent-application-control", "--attest-claude-effective-policy"},
	{"/uninstall", "PURGE=1"},
	{"--action=install", `--install-root=C:\cert\root`, `--state-root=C:\cert\state`, "--gateway-service-name=G", "--guardian-service-name=H",
		`--certification-codex-home=C:\cert\codex`, "--allow-unsigned", "--core-hardening-certification", "--config=a", "--manifest=b"},
	{"/ensure"},
	{"--action=ensure"},
	{"--action", "install", "--config=a", "--manifest=b", "--allowed-signers=" + strings.Repeat("ab", 32)},
	{"/install", "--config=a", "--manifest=b", "ALLOWEDSIGNERS=" + strings.Repeat("ab", 32)},
	{"/status", "--mode=observe", "--connector=codex"},
	{"/status", "--no-start"},
	{"/status", "--purge"},
	{"/install", "--mode=observe", "--connector=copilot"},
	{"/install", "--mode=observe"},
	{"/install", "--mode=watch", "--connector=codex"},
	{"/install", "--mode=observe", "--connector=codex", "--config=a"},
	{"/install", "--mode=observe", "--connector=codex", "--deferred-config"},
	{"/install"},
	{"/upgrade", "--deferred-config"},
	{"/uninstall", "--timeout-seconds=59"},
	{"/install", "--config=a", "--manifest=b", "ALLOWUNSIGNED=1"},
	{"/install", "--config=a", "--manifest=b", "--core-hardening-certification"},
	{"/install", "NOSTART=maybe"},
	{"--bogus"},
	{"/status", "extra"},
}

type secureClientSetupGoldenOptions struct {
	Action                        string `json:"action"`
	Config                        string `json:"config"`
	Manifest                      string `json:"manifest"`
	Mode                          string `json:"mode"`
	Connector                     string `json:"connector"`
	InstallRoot                   string `json:"install_root"`
	StateRoot                     string `json:"state_root"`
	GatewayServiceName            string `json:"gateway_service_name"`
	GuardianServiceName           string `json:"guardian_service_name"`
	CertificationCodexHome        string `json:"certification_codex_home"`
	NoStart                       bool   `json:"no_start"`
	Purge                         bool   `json:"purge"`
	JSON                          bool   `json:"json"`
	AllowUnsigned                 bool   `json:"allow_unsigned"`
	CoreHardeningCertification    bool   `json:"core_hardening_certification"`
	AttestAgentApplicationControl bool   `json:"attest_agent_application_control"`
	AttestClaudeEffectivePolicy   bool   `json:"attest_claude_effective_policy"`
	DeferredConfig                bool   `json:"deferred_config"`
	LifecycleTimeoutSeconds       int64  `json:"lifecycle_timeout_seconds"`
}

type secureClientSetupGoldenCase struct {
	Arguments   []string                        `json:"arguments"`
	Help        bool                            `json:"help"`
	Error       string                          `json:"error,omitempty"`
	FailureText string                          `json:"failure_text,omitempty"`
	FailureJSON string                          `json:"failure_json,omitempty"`
	Options     *secureClientSetupGoldenOptions `json:"options,omitempty"`
}

func secureClientSetupGoldenOptionsFor(opts enterpriseSetupOptions) *secureClientSetupGoldenOptions {
	return &secureClientSetupGoldenOptions{
		Action: opts.Action, Config: opts.Config, Manifest: opts.Manifest, Mode: opts.Mode, Connector: opts.Connector,
		InstallRoot: opts.InstallRoot, StateRoot: opts.StateRoot,
		GatewayServiceName: opts.GatewayServiceName, GuardianServiceName: opts.GuardianServiceName,
		CertificationCodexHome: opts.CertificationCodexHome,
		NoStart:                opts.NoStart, Purge: opts.Purge, JSON: opts.JSON,
		AllowUnsigned: opts.AllowUnsigned, CoreHardeningCertification: opts.CoreHardeningCertification,
		AttestAgentApplicationControl: opts.AttestAgentApplicationControl,
		AttestClaudeEffectivePolicy:   opts.AttestClaudeEffectivePolicy,
		DeferredConfig:                opts.DeferredConfig,
		LifecycleTimeoutSeconds:       int64(opts.LifecycleTimeout.Seconds()),
	}
}

// Secure Client golden: the Secure Client Setup's usage text, parsed options
// and refusal messages. They must stay byte-identical when other Setup
// flavors are added. See testdata/secure_client_golden/README.md.
func TestSecureClientGoldenSetupCommandLine(t *testing.T) {
	var usage bytes.Buffer
	writeEnterpriseSetupUsage(&usage)
	record := map[string]any{"usage": usage.String()}
	cases := make([]secureClientSetupGoldenCase, 0, len(secureClientSetupGoldenCases))
	for _, arguments := range secureClientSetupGoldenCases {
		opts, help, err := parseEnterpriseSetupOptions(arguments)
		entry := secureClientSetupGoldenCase{Arguments: append([]string{}, arguments...), Help: help}
		switch {
		case help:
		case err != nil:
			entry.Error = err.Error()
			var stdout, stderr bytes.Buffer
			writeEnterpriseSetupFailure(&stdout, &stderr, opts, err)
			entry.FailureText = stderr.String()
			opts.JSON = true
			stdout.Reset()
			writeEnterpriseSetupFailure(&stdout, &stderr, opts, err)
			entry.FailureJSON = stdout.String()
		default:
			entry.Options = secureClientSetupGoldenOptionsFor(opts)
		}
		cases = append(cases, entry)
	}
	record["cases"] = cases
	testenv.CompareSecureClientGoldenJSON(t, "go/setup_command_line.json", record)
}
