// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package cli

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The standalone managed hook runtime on Linux and macOS.
//
// The administrator-owned hook binary (/opt/defenseclaw/bin/defenseclaw-hook
// or /opt/cisco/defenseclaw/bin/defenseclaw-hook) runs as the agent's user.
// Everything security-relevant it needs comes from the root-owned runtime
// descriptor the lifecycle writes — never from the user's environment,
// flags or files: the gateway address, the hook socket and the gateway
// service uid the listener must run as.
//
// A hook invoked with --enterprise-managed is a no-op only after an
// administrator removed DefenseClaw: the descriptor is gone AND no
// DefenseClaw-owned vendor machine policy still names the hook for this
// connector. A descriptor that is missing while that policy remains, or a
// descriptor that fails its trust checks, fails closed.

const (
	standaloneRuntimeReasonInvalid           = "enterprise_managed_runtime_state_invalid"
	standaloneRuntimeReasonDescriptorMissing = "enterprise_managed_runtime_descriptor_missing"
	standaloneMachinePolicyReadLimit         = 1 << 20
)

// Test seams.
var (
	standaloneHookGOOS               = runtime.GOOS
	standaloneRuntimeDescriptorLoad  = managed.LoadRuntimeDescriptor
	standaloneMachinePolicyMarkers   = defaultStandaloneMachinePolicyMarkers
	standaloneSecureClientInstallDir = "/opt/cisco/secureclient/defenseclaw"
)

var standaloneHookRuntime struct {
	sync.Mutex
	prepared   bool
	connector  string
	layout     managed.StandaloneLayout
	descriptor *managed.RuntimeDescriptor
	reason     string
}

func trustedNativeHookHome() (string, bool) { return "", false }

// NativeHookRuntimeNoop is the Windows stable-launcher tombstone; unix has
// no such launcher.
func NativeHookRuntimeNoop() bool { return false }

func NativeConnectorHookNoop([]string) bool { return false }

func enterpriseManagedHookRuntimeNoop(connectorName string) bool {
	connectorName = strings.ToLower(strings.TrimSpace(connectorName))
	layout, err := managed.StandaloneLayoutFor(standaloneHookGOOS)
	var loaded *managed.RuntimeDescriptor
	if err == nil {
		loaded, err = standaloneRuntimeDescriptorLoad(layout.DescriptorPath)
	}
	reason := ""
	noop := false
	switch {
	case err == nil:
	case errors.Is(err, managed.ErrNoRuntimeDescriptor):
		switch {
		case standaloneHookGOOS == "darwin" && pathExists(standaloneSecureClientInstallDir):
			// A Secure Client host never uses this runtime; keep its
			// historical fail-closed result for --enterprise-managed.
			reason = standaloneRuntimeReasonInvalid
		case standaloneMachinePolicyPresent(standaloneHookGOOS, connectorName):
			reason = standaloneRuntimeReasonDescriptorMissing
		default:
			noop = true
		}
	default:
		reason = standaloneRuntimeReasonInvalid
	}
	standaloneHookRuntime.Lock()
	standaloneHookRuntime.prepared = true
	standaloneHookRuntime.connector = connectorName
	standaloneHookRuntime.layout = layout
	standaloneHookRuntime.descriptor = loaded
	standaloneHookRuntime.reason = reason
	if noop || reason != "" {
		standaloneHookRuntime.descriptor = nil
	}
	standaloneHookRuntime.Unlock()
	return noop
}

func enterpriseManagedHookRuntimeForceClosed() bool {
	standaloneHookRuntime.Lock()
	defer standaloneHookRuntime.Unlock()
	return standaloneHookRuntime.prepared && standaloneHookRuntime.reason != ""
}

func enterpriseManagedHookRuntimeFailureReason() string {
	standaloneHookRuntime.Lock()
	defer standaloneHookRuntime.Unlock()
	if !standaloneHookRuntime.prepared {
		return ""
	}
	return standaloneHookRuntime.reason
}

func enterpriseManagedHookRuntimeEndpoint(connectorName string) (string, string, bool) {
	addr, service, _, ok := enterpriseManagedHookRuntimeConnection(connectorName)
	return addr, service, ok
}

// enterpriseManagedHookRuntimeConnection returns the descriptor's gateway
// address. There is no service name and no scoped token: the standalone
// transport authenticates the gateway by uid, and the gateway authenticates
// this process by uid (or, on the TCP fallback, by the per-user token file).
func enterpriseManagedHookRuntimeConnection(connectorName string) (string, string, *string, bool) {
	connectorName = strings.ToLower(strings.TrimSpace(connectorName))
	standaloneHookRuntime.Lock()
	defer standaloneHookRuntime.Unlock()
	if !standaloneHookRuntime.prepared || standaloneHookRuntime.reason != "" ||
		standaloneHookRuntime.descriptor == nil || standaloneHookRuntime.connector != connectorName {
		return "", "", nil, false
	}
	return standaloneHookRuntime.descriptor.APIAddr, "", nil, true
}

// applyStandaloneManagedHookTransport binds the managed options to the
// descriptor after buildHookOptionsForRuntime resolved the endpoint:
// the unix socket and service uid select the verified transport, and the
// inherited environment may only tighten the result.
func applyStandaloneManagedHookTransport(opts *hookexec.Options, connectorName string) {
	if opts == nil || !opts.ManagedEnterprise || opts.ManagedRuntimeFailure != "" {
		return
	}
	connectorName = strings.ToLower(strings.TrimSpace(connectorName))
	standaloneHookRuntime.Lock()
	descriptor := standaloneHookRuntime.descriptor
	layout := standaloneHookRuntime.layout
	matches := standaloneHookRuntime.prepared && standaloneHookRuntime.reason == "" &&
		standaloneHookRuntime.connector == connectorName
	standaloneHookRuntime.Unlock()
	if !matches || descriptor == nil {
		return
	}
	opts.ManagedStandalone = true
	opts.ManagedServiceUID = descriptor.ServiceUID
	opts.ManagedUnixSocket = descriptor.HookSocket
	// An inherited generic gateway token never authenticates a managed hook.
	opts.Token = ""
	if opts.MaxBody <= 0 || opts.MaxBody > 1<<20 {
		opts.MaxBody = 1 << 20
	}
	if descriptor.HookSocket != "" {
		// Machine-policy connectors run this hook for users who have no
		// per-user DefenseClaw directory. Anchor Home at the
		// administrator-owned config directory: it always exists, and a user
		// cannot create a .disabled sentinel there.
		opts.Home = layout.ConfigDir
		opts.HookDir = filepath.Join(layout.ConfigDir, "hooks")
	}
}

// standaloneMachinePolicyPresent reports whether DefenseClaw-owned vendor
// machine policy still names the managed hook for connectorName.
func standaloneMachinePolicyPresent(goos, connectorName string) bool {
	for _, marker := range standaloneMachinePolicyMarkers(goos, connectorName) {
		info, err := os.Lstat(marker.path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		if marker.needle == "" {
			return true
		}
		file, err := os.Open(marker.path)
		if err != nil {
			// Unreadable policy is treated as present: fail closed.
			return true
		}
		data, readErr := io.ReadAll(io.LimitReader(file, standaloneMachinePolicyReadLimit))
		_ = file.Close()
		if readErr != nil || bytes.Contains(data, []byte(marker.needle)) {
			return true
		}
	}
	return false
}

type standaloneMachinePolicyMarker struct {
	path   string
	needle string // required content; "" means the file itself is DefenseClaw-owned
}

// defaultStandaloneMachinePolicyMarkers lists the DefenseClaw-owned vendor
// machine-policy files per connector. The machine-policy publisher must
// keep these names (or update this table) so an uninstall that left policy
// behind is detected.
func defaultStandaloneMachinePolicyMarkers(goos, connectorName string) []standaloneMachinePolicyMarker {
	const hookNeedle = "defenseclaw-hook"
	claudeDir := "/etc/claude-code"
	cursorHooks := "/etc/cursor/hooks.json"
	openCodeDir := "/etc/opencode"
	ampSettings := "/etc/ampcode/managed-settings.json"
	if goos == "darwin" {
		claudeDir = "/Library/Application Support/ClaudeCode"
		cursorHooks = "/Library/Application Support/Cursor/hooks.json"
		openCodeDir = "/Library/Application Support/opencode"
		ampSettings = "/Library/Application Support/ampcode/managed-settings.json"
	}
	switch connectorName {
	case "codex":
		return []standaloneMachinePolicyMarker{{path: "/etc/codex/requirements.toml", needle: hookNeedle}}
	case "claudecode":
		return []standaloneMachinePolicyMarker{{path: filepath.Join(claudeDir, "managed-settings.d", "90-defenseclaw.json")}}
	case "cursor":
		return []standaloneMachinePolicyMarker{{path: cursorHooks, needle: hookNeedle}}
	case "copilot":
		return []standaloneMachinePolicyMarker{{path: "/etc/github-copilot/policy.d/90-defenseclaw.json"}}
	case "opencode":
		return []standaloneMachinePolicyMarker{
			{path: filepath.Join(openCodeDir, "opencode.json"), needle: "defenseclaw"},
			{path: filepath.Join(openCodeDir, "opencode.jsonc"), needle: "defenseclaw"},
		}
	case "amp":
		return []standaloneMachinePolicyMarker{{path: ampSettings, needle: "defenseclaw"}}
	default:
		return nil
	}
}

func pathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}
