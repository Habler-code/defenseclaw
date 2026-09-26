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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

const snapshotIndexName = "index.json"

// snapshotEntry records one canonical path before a transaction touched it.
type snapshotEntry struct {
	Path    string      `json:"path"`
	Present bool        `json:"present"`
	Dir     bool        `json:"dir,omitempty"`
	Mode    os.FileMode `json:"mode,omitempty"`
	UID     int         `json:"uid,omitempty"`
	GID     int         `json:"gid,omitempty"`
	Blob    string      `json:"blob,omitempty"`
}

type snapshot struct {
	Dir     string          `json:"-"`
	Entries []snapshotEntry `json:"entries"`
}

// takeSnapshot preserves every canonical path in files (regular files) and
// dirs (mode and owner only) under a fresh directory in the lifecycle
// state. The returned directory is recorded in the pending intent before
// the first mutation.
func (e *Env) takeSnapshot(id string, files, dirs []string) (*snapshot, error) {
	dir := filepath.Join(e.P(e.Layout.LifecycleDir), snapshotsDirName, id)
	if err := os.MkdirAll(filepath.Join(dir, "files"), 0o700); err != nil {
		return nil, fmt.Errorf("create snapshot: %w", err)
	}
	snap := &snapshot{Dir: dir}
	seen := map[string]bool{}
	for index, canonical := range files {
		if seen[canonical] {
			continue
		}
		seen[canonical] = true
		path := e.P(canonical)
		entry := snapshotEntry{Path: canonical}
		uid, gid, mode, err := statOwnerMode(path)
		switch {
		case errors.Is(err, os.ErrNotExist):
		case err != nil:
			return nil, fmt.Errorf("snapshot %s: %w", canonical, err)
		case mode&os.ModeSymlink != 0:
			return nil, fmt.Errorf("snapshot %s: refusing to snapshot a symlink", canonical)
		case !mode.IsRegular():
			return nil, fmt.Errorf("snapshot %s: not a regular file", canonical)
		default:
			blob := strconv.Itoa(index)
			if err := linkOrCopy(path, filepath.Join(dir, "files", blob)); err != nil {
				return nil, fmt.Errorf("snapshot %s: %w", canonical, err)
			}
			entry.Present, entry.Mode, entry.UID, entry.GID, entry.Blob = true, mode.Perm(), uid, gid, blob
		}
		snap.Entries = append(snap.Entries, entry)
	}
	for _, canonical := range dirs {
		if seen[canonical] {
			continue
		}
		seen[canonical] = true
		entry := snapshotEntry{Path: canonical, Dir: true}
		uid, gid, mode, err := statOwnerMode(e.P(canonical))
		if err == nil && mode.IsDir() {
			entry.Present, entry.Mode, entry.UID, entry.GID = true, mode.Perm(), uid, gid
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("snapshot %s: %w", canonical, err)
		}
		snap.Entries = append(snap.Entries, entry)
	}
	data, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := e.writeFileAtomic(filepath.Join(dir, snapshotIndexName), data, 0o600, rootOwner()); err != nil {
		return nil, err
	}
	return snap, nil
}

func (e *Env) loadSnapshot(dir string) (*snapshot, error) {
	data, err := readBounded(filepath.Join(dir, snapshotIndexName), maxInputBytes)
	if err != nil {
		return nil, fmt.Errorf("read snapshot index: %w", err)
	}
	snap := &snapshot{Dir: dir}
	if err := json.Unmarshal(data, snap); err != nil {
		return nil, fmt.Errorf("parse snapshot index: %w", err)
	}
	return snap, nil
}

// restore puts every file back exactly as snapshotted and removes files
// that did not exist before. Directories only get their mode and owner
// back; directories the transaction created stay (they are harmless and
// uninstall owns their removal).
func (e *Env) restore(snap *snapshot) error {
	var errs []error
	for _, entry := range snap.Entries {
		path := e.P(entry.Path)
		switch {
		case entry.Dir:
			if entry.Present {
				if err := os.Chmod(path, entry.Mode); err != nil && !errors.Is(err, os.ErrNotExist) {
					errs = append(errs, err)
				}
				if err := e.Lchown(path, entry.UID, entry.GID); err != nil && !errors.Is(err, os.ErrNotExist) {
					errs = append(errs, err)
				}
			}
		case entry.Present:
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				errs = append(errs, err)
				continue
			}
			blob := filepath.Join(snap.Dir, "files", entry.Blob)
			if err := e.copyFileAtomic(blob, path, entry.Mode, fileOwner{UID: entry.UID, GID: entry.GID}); err != nil {
				errs = append(errs, fmt.Errorf("restore %s: %w", entry.Path, err))
			}
		default:
			if err := removeFile(path); err != nil {
				errs = append(errs, fmt.Errorf("remove %s: %w", entry.Path, err))
			}
		}
	}
	return errors.Join(errs...)
}

func (e *Env) discardSnapshot(snap *snapshot) {
	if snap != nil && snap.Dir != "" {
		_ = os.RemoveAll(snap.Dir)
	}
}
