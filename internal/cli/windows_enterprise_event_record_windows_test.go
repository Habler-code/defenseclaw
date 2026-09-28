// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// WIN-F30: a DefenseClaw Application-log event carries a record id that the
// administrator-only lifecycle log holds with the event ID and the SHA-256 of
// the exact message, so an entry another account wrote under the same source
// can be told apart.
func TestWindowsEnterpriseEventCarriesARecordTheLifecycleLogHolds(t *testing.T) {
	previousID, previousWriter := windowsEnterpriseEventRecordID, windowsEnterpriseEventWriter
	t.Cleanup(func() { windowsEnterpriseEventRecordID, windowsEnterpriseEventWriter = previousID, previousWriter })
	windowsEnterpriseEventRecordID = func() (string, error) { return "0123456789abcdef0123456789abcdef", nil }
	var written string
	var writtenID uint32
	windowsEnterpriseEventWriter = func(id uint32, _ string, message string) error {
		writtenID, written = id, message
		return nil
	}

	result := enterprisestatus.New("install", "standalone", "windows", "1.0.51")
	result.Finish("windows", 0)
	event := writeWindowsEnterpriseEvent(result)
	if event == nil {
		t.Fatal("no event record for a finished install")
	}
	if !strings.HasSuffix(written, "\r\nrecord 0123456789abcdef0123456789abcdef") {
		t.Fatalf("event message does not end with its record:\n%s", written)
	}
	digest := sha256.Sum256([]byte(written))
	if event.ID != writtenID || event.Record != "0123456789abcdef0123456789abcdef" || event.SHA256 != hex.EncodeToString(digest[:]) {
		t.Fatalf("event record %+v does not match the written event (id %d)", event, writtenID)
	}

	directory := t.TempDir()
	if _, err := writeWindowsEnterpriseLifecycleLog(directory, result, event); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(filepath.Join(directory, windowsEnterpriseLogName))
	if err != nil {
		t.Fatal(err)
	}
	var line struct {
		Event *windowsEnterpriseEventRecord `json:"event"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(body))), &line); err != nil {
		t.Fatal(err)
	}
	if line.Event == nil || *line.Event != *event {
		t.Fatalf("lifecycle log event = %+v, want %+v", line.Event, event)
	}
}

// A run whose event could not be written records no event in the log.
func TestWindowsEnterpriseEventWriteFailureRecordsNothing(t *testing.T) {
	previousWriter := windowsEnterpriseEventWriter
	t.Cleanup(func() { windowsEnterpriseEventWriter = previousWriter })
	windowsEnterpriseEventWriter = func(uint32, string, string) error { return os.ErrPermission }
	result := enterprisestatus.New("install", "standalone", "windows", "1.0.51")
	result.Finish("windows", 0)
	if event := writeWindowsEnterpriseEvent(result); event != nil {
		t.Fatalf("a failed event write returned record %+v", event)
	}
}
