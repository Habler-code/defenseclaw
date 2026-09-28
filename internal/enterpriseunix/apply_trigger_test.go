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
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeChangedConfig(t *testing.T, h *testHost, from, to string) string {
	t.Helper()
	cfg := filepath.Join(t.TempDir(), "config.yaml")
	changed := strings.Replace(string(DefaultConfig(h.env.Layout)), from, to, 1)
	if err := os.WriteFile(cfg, []byte(changed), 0o600); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func touched(calls []string, unit string) []string {
	var out []string
	for _, call := range calls {
		if call == "stop "+unit || call == "start "+unit || call == "restart "+unit {
			out = append(out, call)
		}
	}
	return out
}

// A transaction's own writes (the snapshot links config.yaml, --config
// rewrites it) fire the apply path unit, whose run then waits for the
// lifecycle lock. Quiesce stopped that waiting run 27 ms later, so every
// `ensure --config` left defenseclaw-enterprise-apply.service failed (seen
// on RHEL and Ubuntu), and an administrator change that fired it was
// dropped. The queued run is left alone through the change and a rollback.
func TestTransactionsLeaveAQueuedApplyRunAlone(t *testing.T) {
	t.Run("linux", func(t *testing.T) {
		h := newTestHost(t, "linux")
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
		h.services.active[unitApplyService] = true // queued, waiting for the lock
		before := len(h.services.calls)
		requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: writeChangedConfig(t, h, "mode: observe", "mode: action")}))
		if calls := touched(h.services.calls[before:], unitApplyService); len(calls) > 0 || !h.services.isActive(unitApplyService) {
			t.Fatalf("ensure stopped the queued apply run: %v", calls)
		}
		h.healthy = false
		before = len(h.services.calls)
		failed := h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("2.0.0")})
		requireError(t, failed, codeActivate)
		if calls := touched(h.services.calls[before:], unitApplyService); len(calls) > 0 || !h.services.isActive(unitApplyService) {
			t.Fatalf("the rollback stopped the queued apply run: %v", calls)
		}
	})
	t.Run("darwin", func(t *testing.T) {
		h := newTestHost(t, "darwin")
		requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
		if !h.services.isActive(labelApply) {
			t.Fatal("the apply job is not loaded after install")
		}
		before := len(h.services.calls)
		requireOK(t, h.run(Options{Action: ActionEnsure, ConfigFile: writeChangedConfig(t, h, "mode: observe", "mode: action")}))
		if calls := touched(h.services.calls[before:], labelApply); len(calls) > 0 || !h.services.isActive(labelApply) {
			t.Fatalf("ensure booted out or kickstarted the apply job: %v", calls)
		}
	})
}

// A failed oneshot sat in status and verify as failed/failed under a green
// check with no warning.
func TestStatusWarnsAboutAFailedOneshot(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	h.services.failed[unitApplyService] = true
	for _, action := range []string{ActionStatus, ActionVerify} {
		r := h.run(Options{Action: action})
		if got := messagesOf(r.Warnings, "unit_failed"); !strings.Contains(got, unitApplyService+" failed") || !strings.Contains(got, "journalctl -u "+unitApplyService) {
			t.Fatalf("%s does not warn about the failed apply service: %+v", action, r.Warnings)
		}
	}
}

// A queued apply run is left alone during a transaction. When that
// transaction upgraded the deployment, the queued run is the previous
// binary: it stands down instead of rendering its older files over the
// upgrade.
func TestAQueuedApplyRunFromAnOlderBinaryStandsDown(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	h.env.ProductVersion = "1.0.1"
	requireOK(t, h.run(Options{Action: ActionUpgrade, PayloadDir: h.payload("1.0.1")}))
	h.env.ProductVersion = "1.0.0" // the run that waited through the upgrade
	before := len(h.services.calls)
	r := h.run(Options{Action: ActionEnsure, Reason: "path", ConfigFile: writeChangedConfig(t, h, "mode: observe", "mode: action")})
	requireOK(t, r)
	if !r.Noop || r.NoopReason != "superseded" || len(h.services.calls) != before {
		t.Fatalf("the older apply run did not stand down: noop=%v reason=%q calls=%v", r.Noop, r.NoopReason, h.services.calls[before:])
	}
	// Any other run, and the apply run of the installed binary, proceed.
	h.env.ProductVersion = "1.0.1"
	if again := h.run(Options{Action: ActionEnsure, Reason: "path"}); again.NoopReason == "superseded" {
		t.Fatal("the installed binary's apply run stood down")
	}
	h.env.ProductVersion = "dev"
	if again := h.run(Options{Action: ActionEnsure, Reason: "path"}); again.NoopReason == "superseded" {
		t.Fatal("a development build stood down")
	}
}
