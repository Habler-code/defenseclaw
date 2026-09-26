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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

// policyFileLimit bounds every vendor policy read. Real files are a few KiB.
const policyFileLimit = 4 << 20

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// readBounded reads an already-opened regular file with a hard size cap.
func readBounded(file *os.File, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s exceeds %d bytes", file.Name(), limit)
	}
	return data, nil
}

// readPolicyFile returns (data, exists). The file must be a regular,
// non-symlink file whose ancestors an unprivileged user cannot replace.
func readPolicyFile(opts Options, path string) ([]byte, bool, error) {
	path = platformPath(opts, path)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if !opts.SkipTrustChecks {
			if err := validateTrustedAncestors(opts, path); err != nil {
				return nil, false, err
			}
		}
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() {
		return nil, false, fmt.Errorf("%s is not a regular file", path)
	}
	if !opts.SkipTrustChecks {
		if err := validateTrustedPolicyFile(opts, path); err != nil {
			return nil, false, err
		}
	}
	file, err := openNoFollow(path)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()
	stat, err := file.Stat()
	if err != nil {
		return nil, false, err
	}
	if !os.SameFile(info, stat) {
		return nil, false, fmt.Errorf("%s changed while it was opened", path)
	}
	data, err := readBounded(file, policyFileLimit)
	if err != nil {
		return nil, false, err
	}
	return data, true, nil
}

// writePolicyFile atomically replaces path with data, creating missing
// parent directories administrator-owned. The file stays readable by every
// local user (agents must read machine policy) and writable only by
// administrators. It returns the directories it created, deepest last.
func writePolicyFile(opts Options, path string, data []byte) ([]string, error) {
	path = platformPath(opts, path)
	created, err := ensurePolicyDir(opts, dirFor(opts, path))
	if err != nil {
		return created, err
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return created, fmt.Errorf("%s exists and is not a regular file", path)
	}
	return created, atomicWrite(opts, path, data, true)
}

// removePolicyFile deletes path if it is a regular file.
func removePolicyFile(opts Options, path string) error {
	path = platformPath(opts, path)
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("refusing to remove non-regular %s", path)
	}
	return os.Remove(path)
}

// removeDirIfEmpty removes a directory DefenseClaw created, only when it
// is empty, so shared vendor parents with other content survive.
func removeDirIfEmpty(opts Options, dir string) error {
	dir = platformPath(opts, dir)
	entries, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return nil
	}
	return os.Remove(dir)
}
