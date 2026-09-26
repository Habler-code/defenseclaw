// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

const ownershipSchemaVersion = 1

// Flapping: this many rewrites of an owned file within the window means a
// second writer (an MDM template, config management) keeps replacing it.
const (
	flapThreshold = 3
	flapWindow    = 24 * time.Hour
	flapKeep      = 10
)

// ownershipRecord remembers what DefenseClaw changed in one vendor file so
// removal can restore the administrator's exact preimage.
type ownershipRecord struct {
	SchemaVersion   int      `json:"schema_version"`
	Connector       string   `json:"connector"`
	Path            string   `json:"path"`
	PreimageExisted bool     `json:"preimage_existed"`
	Preimage        []byte   `json:"preimage,omitempty"`
	PreimageSHA256  string   `json:"preimage_sha256"`
	PostimageSHA256 string   `json:"postimage_sha256"`
	CreatedDirs     []string `json:"created_dirs,omitempty"`
	Rewrites        []string `json:"rewrites,omitempty"`
	UpdatedAt       string   `json:"updated_at"`
}

var recordNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

func recordPath(opts Options, connector string) (string, error) {
	if opts.StateDir == "" {
		return "", errors.New("enterprise policy: ownership state directory is required")
	}
	if !recordNamePattern.MatchString(connector) {
		return "", fmt.Errorf("enterprise policy: invalid connector name %q", connector)
	}
	return filepath.Join(opts.StateDir, connector+".json"), nil
}

func loadRecord(opts Options, connector string) (*ownershipRecord, error) {
	path, err := recordPath(opts, connector)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	file, err := openNoFollow(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := readBounded(file, 2*policyFileLimit)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var record ownershipRecord
	if err := decoder.Decode(&record); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	if record.SchemaVersion != ownershipSchemaVersion || record.Connector != connector {
		return nil, fmt.Errorf("%s is not a %s ownership record", path, connector)
	}
	if record.PreimageExisted && sha256Hex(record.Preimage) != record.PreimageSHA256 {
		return nil, fmt.Errorf("%s preimage digest does not match its bytes", path)
	}
	return &record, nil
}

func saveRecord(opts Options, record *ownershipRecord) error {
	path, err := recordPath(opts, record.Connector)
	if err != nil {
		return err
	}
	if err := ensurePrivateDir(opts.StateDir); err != nil {
		return err
	}
	record.SchemaVersion = ownershipSchemaVersion
	record.UpdatedAt = opts.now().Format(time.RFC3339)
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(opts, path, append(data, '\n'), false)
}

func deleteRecord(opts Options, connector string) error {
	path, err := recordPath(opts, connector)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// beginRecord returns the existing record or a new one capturing the
// current file as the preimage.
func beginRecord(opts Options, connector, path string, current []byte, exists bool) (*ownershipRecord, error) {
	record, err := loadRecord(opts, connector)
	if err != nil {
		return nil, err
	}
	if record != nil && record.Path == path {
		return record, nil
	}
	record = &ownershipRecord{Connector: connector, Path: path, PreimageExisted: exists}
	if exists {
		record.Preimage = append([]byte(nil), current...)
		record.PreimageSHA256 = sha256Hex(current)
	}
	return record, nil
}

// noteRewrite records that the owned entries were found missing from a
// file DefenseClaw had written; it returns how many rewrites happened in
// the flap window.
func (r *ownershipRecord) noteRewrite(now time.Time) int {
	r.Rewrites = append(r.Rewrites, now.Format(time.RFC3339))
	if len(r.Rewrites) > flapKeep {
		r.Rewrites = r.Rewrites[len(r.Rewrites)-flapKeep:]
	}
	count := 0
	for _, stamp := range r.Rewrites {
		when, err := time.Parse(time.RFC3339, stamp)
		if err == nil && now.Sub(when) <= flapWindow {
			count++
		}
	}
	return count
}

func flapConflict(state *State, connector, path string, count int) {
	if count >= flapThreshold {
		state.conflict("another writer replaced %s %d times in 24h and removed DefenseClaw's hooks each time; if an MDM or configuration tool owns this file, set enterprise.machine_policy.connectors.%s.ownership: verify_only and deploy the output of `defenseclaw-gateway enterprise policy export --connector %s` through that tool", path, count, connector, connector)
	}
}

// publishWithRecord writes rendered when it differs from current and keeps
// the ownership record in sync. It returns whether the file changed.
func publishWithRecord(opts Options, connector, path string, current []byte, exists bool, rendered []byte, ownedWasPresent bool, state *State) (bool, error) {
	record, err := beginRecord(opts, connector, path, current, exists)
	if err != nil {
		return false, err
	}
	if record.PostimageSHA256 != "" && exists && sha256Hex(current) != record.PostimageSHA256 && !ownedWasPresent {
		flapConflict(state, connector, path, record.noteRewrite(opts.now()))
	}
	changed := !exists || !bytes.Equal(current, rendered)
	if changed {
		created, err := writePolicyFile(opts, path, rendered)
		record.CreatedDirs = appendUnique(record.CreatedDirs, created...)
		if err != nil {
			return false, err
		}
	}
	record.PostimageSHA256 = sha256Hex(rendered)
	if err := saveRecord(opts, record); err != nil {
		return changed, err
	}
	return changed, nil
}

// restoreOrStrip removes DefenseClaw's content from path. When the file is
// exactly what DefenseClaw last wrote, the preimage is restored byte for
// byte (or the file removed when it did not exist); otherwise strip is
// applied to the current bytes so later administrator edits survive.
func restoreOrStrip(opts Options, connector, path string, strip func([]byte) ([]byte, bool, error), state *State) error {
	record, err := loadRecord(opts, connector)
	if err != nil {
		return err
	}
	current, exists, err := readPolicyFile(opts, path)
	if err != nil {
		return err
	}
	if record != nil && record.Path == path && exists && sha256Hex(current) == record.PostimageSHA256 {
		if record.PreimageExisted {
			if _, err := writePolicyFile(opts, path, record.Preimage); err != nil {
				return err
			}
			state.detail("restored the preimage of %s", path)
		} else {
			if err := removePolicyFile(opts, path); err != nil {
				return err
			}
			state.detail("removed %s (it did not exist before DefenseClaw)", path)
		}
		state.Changed = true
	} else if exists {
		stripped, empty, err := strip(current)
		if err != nil {
			return err
		}
		switch {
		case empty && (record == nil || !record.PreimageExisted):
			if err := removePolicyFile(opts, path); err != nil {
				return err
			}
			state.Changed = true
		case !bytes.Equal(stripped, current):
			if _, err := writePolicyFile(opts, path, stripped); err != nil {
				return err
			}
			state.Changed = true
			state.detail("%s changed after DefenseClaw wrote it; removed only DefenseClaw entries", path)
		}
	}
	if record != nil {
		for i := len(record.CreatedDirs) - 1; i >= 0; i-- {
			if err := removeDirIfEmpty(opts, record.CreatedDirs[i]); err != nil {
				state.detail("left %s in place: %v", record.CreatedDirs[i], err)
			}
		}
	}
	return deleteRecord(opts, connector)
}

func appendUnique(list []string, values ...string) []string {
	for _, value := range values {
		found := false
		for _, existing := range list {
			if existing == value {
				found = true
				break
			}
		}
		if !found {
			list = append(list, value)
		}
	}
	return list
}
