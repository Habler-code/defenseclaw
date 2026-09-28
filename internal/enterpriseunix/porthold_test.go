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
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// plantLinuxListener makes the rooted /proc show pid listening on
// 127.0.0.1:18970 as uid.
func plantLinuxListener(t *testing.T, h *testHost, pid, uid string) {
	t.Helper()
	tcp := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:4A1A 00000000:0000 0A 00000000:00000000 00:00000000 00000000  " + uid + "        0 777001 1 0000000000000000 100 0 0 10 0\n" +
		"   1: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 777002 1 0000000000000000 100 0 0 10 0\n"
	writeHostFile(t, h, "/proc/net/tcp", tcp)
	fd := h.env.P(filepath.Join("/proc", pid, "fd"))
	if err := os.MkdirAll(fd, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[777001]", filepath.Join(fd, "7")); err != nil {
		t.Fatal(err)
	}
	other := h.env.P("/proc/4000/fd")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[777002]", filepath.Join(other, "3")); err != nil {
		t.Fatal(err)
	}
}

// lsofRunner answers lsof like macOS does for a listener on the API port.
type lsofRunner struct {
	Runner
	output string
}

func (r lsofRunner) Run(ctx context.Context, name string, args ...string) (CommandResult, error) {
	if name == "lsof" {
		return CommandResult{Stdout: []byte(r.output)}, nil
	}
	return r.Runner.Run(ctx, name, args...)
}

// RHEL-F21, UBU-F19: with the socket units stopped another account bound
// 127.0.0.1:18970. Repair failed with systemd's "Job failed. See journalctl
// -xe" and status reported "gateway health: ... EOF" (the probe reached the
// other process); neither named it.
func TestLinuxPortHolderIsNamedByVerifyAndRepair(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	plantLinuxListener(t, h, "31337", "4242")
	h.services.active[unitAPISocket] = false
	h.services.active[unitGateway] = false
	h.env.HealthGet = func(context.Context) (int, []byte, error) {
		return 0, nil, errors.New(`Get "http://127.0.0.1:18970/health": EOF`)
	}
	want := "the gateway API port 127.0.0.1:18970 is held by pid 31337 (uid 4242"

	status := h.run(Options{Action: ActionStatus})
	if got := messagesOf(status.Warnings, codeVerify); !strings.Contains(got, want) || strings.Contains(got, "EOF") || !strings.Contains(got, "enterprise linux repair`") {
		t.Fatalf("status does not name the port holder: %s", got)
	}
	if status.Readiness.Gateway {
		t.Fatal("status reports the gateway ready")
	}

	h.services.failStart[unitAPISocket] = errors.New("systemctl start defenseclaw-gateway-api.socket: exit 1: Job for defenseclaw-gateway-api.socket failed. See \"journalctl -xe\" for details.")
	repair := h.run(Options{Action: ActionRepair})
	requireError(t, repair, codeActivate)
	if got := messagesOf(repair.Errors, codeActivate); !strings.Contains(got, want) {
		t.Fatalf("repair does not name the port holder: %s", got)
	}
}

// MAC-F24: while another account held 127.0.0.1:18970 across a gateway
// restart, status said only "gateway health returned HTTP 503" (the other
// listener's answer) and nothing about the gateway serving the hook socket.
func TestDarwinPortHolderIsNamedAndNotTrusted(t *testing.T) {
	h := newTestHost(t, "darwin")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	h.env.Runner = lsofRunner{Runner: h.runner, output: "p94782\nu4243\nf5\n"}
	for name, answer := range map[string]int{"503": 503, "200": 200} {
		t.Run(name, func(t *testing.T) {
			h.env.HealthGet = func(context.Context) (int, []byte, error) { return answer, []byte(`{}`), nil }
			status := h.run(Options{Action: ActionStatus})
			got := messagesOf(status.Warnings, codeVerify)
			if !strings.Contains(got, "is held by pid 94782 (uid 4243") || !strings.Contains(got, "serves hooks on its socket and keeps retrying the port") {
				t.Fatalf("status does not name the port holder: %s", got)
			}
			if status.Readiness.Gateway {
				t.Fatal("status trusted the other listener's /health answer")
			}
		})
	}
}
