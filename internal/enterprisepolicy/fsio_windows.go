//go:build windows

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
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Protected descriptors: SYSTEM and Administrators own and write; standard
// users read policy (agents must load it) but never records.
const (
	publicFileSDDL   = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"
	privateFileSDDL  = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
	publicDirSDDL    = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
	privateDirSDDL   = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	adminOwnerSIDStr = "S-1-5-32-544"
)

var trustedOwner = func(uint32) bool { return true }

func platformPath(_ Options, path string) string { return path }

func validateTrustedAncestors(opts Options, path string) error {
	for dir := filepath.Dir(path); ; dir = filepath.Dir(dir) {
		if _, err := os.Lstat(dir); err == nil {
			return managed.ValidateTrustedDirectoryAncestor(dir, "machine policy directory")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if dir == filepath.Dir(dir) {
			return fmt.Errorf("%s has no existing ancestor", path)
		}
	}
}

func validateTrustedPolicyFile(_ Options, path string) error {
	return managed.ValidateTrustedFilePath(path, "machine policy file")
}

func openNoFollow(path string) (*os.File, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || info.Mode()&os.ModeIrregular != 0 {
		return nil, fmt.Errorf("%s is a reparse point", path)
	}
	return os.Open(path)
}

func applySDDL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	owner, err := windows.StringToSid(adminOwnerSIDStr)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil,
	)
}

func ensurePolicyDir(opts Options, dir string) ([]string, error) {
	var missing []string
	for cur := dir; ; cur = filepath.Dir(cur) {
		if _, err := os.Lstat(cur); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		missing = append([]string{cur}, missing...)
		if cur == filepath.Dir(cur) {
			break
		}
	}
	if !opts.SkipTrustChecks {
		if err := validateTrustedAncestors(opts, filepath.Join(dir, "x")); err != nil {
			return nil, err
		}
	}
	created := []string{}
	for _, cur := range missing {
		if err := os.Mkdir(cur, 0o755); err != nil && !errors.Is(err, os.ErrExist) {
			return created, err
		}
		if err := applySDDL(cur, publicDirSDDL); err != nil {
			return created, err
		}
		created = append(created, cur)
	}
	return created, nil
}

func atomicWrite(_ Options, path string, data []byte, public bool) error {
	dir := filepath.Dir(path)
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	tmp := filepath.Join(dir, "."+filepath.Base(path)+".defenseclaw-"+hex.EncodeToString(suffix))
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	cleanup := func() { _ = os.Remove(tmp) }
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		cleanup()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		cleanup()
		return err
	}
	if err := file.Close(); err != nil {
		cleanup()
		return err
	}
	sddl := privateFileSDDL
	if public {
		sddl = publicFileSDDL
	}
	if err := applySDDL(tmp, sddl); err != nil {
		cleanup()
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		cleanup()
		return err
	}
	return nil
}

func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return applySDDL(dir, privateDirSDDL)
}
