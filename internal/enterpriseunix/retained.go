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
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// A non-purge uninstall keeps the gateway state and the guardian ledger so a
// reinstall resumes with the same audit history and device identity. It
// records the identity of each directory it kept, so the next install
// recognizes its own retained state instead of refusing it as an unmanaged
// layout. A directory that was replaced, recreated or re-owned since then no
// longer matches and is still treated as foreign.
const (
	retainedStateFileName      = "retained-state.json"
	retainedStateSchemaVersion = 1
)

type retainedState struct {
	SchemaVersion int           `json:"schema_version"`
	RecordedAt    string        `json:"recorded_at"`
	Dirs          []retainedDir `json:"dirs"`
}

type retainedDir struct {
	Path  string `json:"path"`
	Dev   uint64 `json:"dev"`
	Inode uint64 `json:"inode"`
	UID   uint32 `json:"uid"`
}

func (e *Env) retainedStatePath() string {
	return filepath.Join(e.P(e.Layout.LifecycleDir), retainedStateFileName)
}

func directoryIdentity(path string) (retainedDir, bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() {
		return retainedDir{}, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return retainedDir{}, false
	}
	return retainedDir{Dev: uint64(stat.Dev), Inode: uint64(stat.Ino), UID: stat.Uid}, true //nolint:unconvert // Dev is int32 on darwin
}

// recordRetainedState notes the non-empty state directories a non-purge
// uninstall leaves behind; with nothing kept it removes any stale record.
func (e *Env) recordRetainedState() error {
	state := retainedState{
		SchemaVersion: retainedStateSchemaVersion,
		RecordedAt:    e.Now().UTC().Format(time.RFC3339),
	}
	for _, dir := range []string{e.Layout.DataDir, e.Layout.GuardianAuthDir} {
		entries, err := os.ReadDir(e.P(dir))
		if err != nil || len(entries) == 0 {
			continue
		}
		identity, ok := directoryIdentity(e.P(dir))
		if !ok {
			continue
		}
		identity.Path = dir
		state.Dirs = append(state.Dirs, identity)
	}
	if len(state.Dirs) == 0 {
		return removeFile(e.retainedStatePath())
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return e.writeFileAtomic(e.retainedStatePath(), append(data, '\n'), 0o600, rootOwner())
}

// loadRetainedState returns the directories the lifecycle kept, keyed by
// layout path. An unreadable or malformed record retains nothing.
func (e *Env) loadRetainedState() map[string]retainedDir {
	data, err := readBounded(e.retainedStatePath(), maxInputBytes)
	if err != nil {
		return nil
	}
	var state retainedState
	if err := decodeStrict(data, &state); err != nil || state.SchemaVersion != retainedStateSchemaVersion {
		return nil
	}
	out := make(map[string]retainedDir, len(state.Dirs))
	for _, dir := range state.Dirs {
		out[dir.Path] = dir
	}
	return out
}

// retainedByLifecycle reports whether dir is the same directory a previous
// non-purge uninstall recorded as kept.
func (e *Env) retainedByLifecycle(dir string, retained map[string]retainedDir) bool {
	want, ok := retained[dir]
	if !ok {
		return false
	}
	got, ok := directoryIdentity(e.P(dir))
	return ok && got.Dev == want.Dev && got.Inode == want.Inode && got.UID == want.UID
}
