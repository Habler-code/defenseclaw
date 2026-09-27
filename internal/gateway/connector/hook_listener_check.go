// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"strings"
)

// The shell hooks source hooks/_hardening.sh, whose listener-owner check
// sits between these marker lines. The block is self-contained POSIX sh, so
// the bridges that do not source the helper (the Codex notify bridge and the
// OpenCode, Amp and OmniGent plugins) embed the same bytes rather than
// carrying a second implementation.
const (
	hookListenerCheckBegin = "# --- BEGIN defenseclaw gateway listener check ---\n"
	hookListenerCheckEnd   = "# --- END defenseclaw gateway listener check ---\n"
)

// hookListenerCheckCall verifies the gateway address in $1. It exits 0 when
// the port may receive the token, and 1 with the refusal reason on stdout.
const hookListenerCheckCall = `defenseclaw_verify_gateway_listener "$1" || { printf '%s' "$DEFENSECLAW_LISTENER_REASON"; exit 1; }` + "\n"

// hookListenerCheckPath is the search path the embedded check runs with, so
// neither an agent-controlled PATH nor the bridge's own environment chooses
// the id, uname, awk, netstat or ps it relies on.
const hookListenerCheckPath = "/usr/bin:/bin:/usr/sbin:/sbin"

// hookListenerCheckBlock returns the listener-owner check functions from
// hooks/_hardening.sh, markers included.
func hookListenerCheckBlock() (string, error) {
	helper, err := hookFS.ReadFile("hooks/_hardening.sh")
	if err != nil {
		return "", fmt.Errorf("read hook hardening helper: %w", err)
	}
	text := string(helper)
	begin := strings.Index(text, hookListenerCheckBegin)
	if begin < 0 || strings.Count(text, hookListenerCheckBegin) != 1 {
		return "", fmt.Errorf("hook hardening helper has no single listener check block")
	}
	end := strings.Index(text[begin:], hookListenerCheckEnd)
	if end < 0 || strings.Count(text, hookListenerCheckEnd) != 1 {
		return "", fmt.Errorf("hook hardening helper has an unterminated listener check block")
	}
	return text[begin : begin+end+len(hookListenerCheckEnd)], nil
}

// hookListenerCheckProgram returns a /bin/sh program that runs the listener
// check against the gateway address passed as $1 (with $0 naming the
// program). Callers run it with PATH=hookListenerCheckPath and set
// DEFENSECLAW_MANAGED_HOOK=1 only for managed installs.
func hookListenerCheckProgram() (string, error) {
	block, err := hookListenerCheckBlock()
	if err != nil {
		return "", err
	}
	return block + hookListenerCheckCall, nil
}
