// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// WIN-F34: the runtime-only per-user route (OpenCode while its machine
// policy is in force) must record the guardian's executable selection the
// same way the full setup route does, or a user whose protected contract
// lock is gone can never be republished.
func TestRecordWindowsManagedSetupSelectionWritesTheGuardianReceipt(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	executable := filepath.Join(testenv.PrivateTempDir(t), "opencode.exe")
	if err := os.WriteFile(executable, []byte("MZ guardian-selected OpenCode image"), 0o700); err != nil {
		t.Fatal(err)
	}
	target := windowsGenericManagedTarget{
		dataDir: dataDir,
		conn:    connector.NewOpenCodeConnector(),
		setup:   connector.SetupOpts{DataDir: dataDir, AgentExecutable: executable, AgentVersion: "1.18.19"},
	}
	if err := recordWindowsManagedSetupSelection(target); err != nil {
		t.Fatalf("record OpenCode selection: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dataDir, "agent_selection.json"))
	if err != nil {
		t.Fatalf("read receipt: %v", err)
	}
	var receipt struct {
		Selections map[string]struct {
			Executable string `json:"executable"`
			SHA256     string `json:"sha256"`
			RawVersion string `json:"raw_version"`
		} `json:"selections"`
	}
	if err := json.Unmarshal(data, &receipt); err != nil {
		t.Fatalf("parse receipt: %v\n%s", err, data)
	}
	selection, ok := receipt.Selections["opencode"]
	if !ok || !sameWindowsEnterprisePath(selection.Executable, executable) || selection.SHA256 == "" {
		t.Fatalf("receipt selection = %+v (present %v), want %s with a digest", selection, ok, executable)
	}

	removeWindowsManagedSetupSelectionReceipt(dataDir)
	for _, name := range []string{"agent_selection.json", "agent_selection.json.lock"} {
		if _, err := os.Lstat(filepath.Join(dataDir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s left behind after receipt removal: %v", name, err)
		}
	}
}

func TestRecordWindowsManagedSetupSelectionSkipsRowsWithoutProtectedAdmission(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	executable := filepath.Join(testenv.PrivateTempDir(t), "copilot.exe")
	if err := os.WriteFile(executable, []byte("MZ copilot image"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, target := range []windowsGenericManagedTarget{
		// Copilot has no protected executable admission.
		{dataDir: dataDir, conn: connector.NewCopilotConnector(), setup: connector.SetupOpts{AgentExecutable: executable, AgentVersion: "1.0.88"}},
		// A row with no selected executable.
		{dataDir: dataDir, conn: connector.NewOpenCodeConnector(), setup: connector.SetupOpts{AgentVersion: "1.18.19"}},
	} {
		if err := recordWindowsManagedSetupSelection(target); err != nil {
			t.Fatalf("%s: %v", target.conn.Name(), err)
		}
	}
	if _, err := os.Lstat(filepath.Join(dataDir, "agent_selection.json")); !os.IsNotExist(err) {
		t.Fatalf("a row without protected admission wrote a receipt: %v", err)
	}
}
