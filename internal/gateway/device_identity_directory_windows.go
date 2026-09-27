// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

func validateDeviceIdentityPathSyntax(target, dataDir string) error {
	for _, path := range []string{target, dataDir} {
		volume := filepath.VolumeName(path)
		if strings.Contains(path[len(volume):], ":") {
			return fmt.Errorf("gateway: device identity paths cannot use Windows alternate data streams")
		}
	}
	return nil
}

// Windows path ownership and full-chain reparse checks are enforced by
// safefile.ValidatePrivateDirectory immediately after this platform hook, or
// for the managed gateway service by managed.ValidateTrustedServiceRuntimeDir.
func validateFreshIdentityDirectoryPlatform(_ string, _ os.FileInfo) error { return nil }

func validateFreshIdentityFilePlatform(string) error { return nil }

// Windows does not support fsync on an opened directory handle. The file
// handle itself is flushed before this hook is reached.
func syncFreshIdentityDirectory(string) error { return nil }

// The managed enterprise gateway service (Secure Client and standalone) keeps
// its device identity in the managed runtime directory. That directory is
// Administrators-owned with a protected DACL: SYSTEM and Administrators full
// control, and Modify for the exact NT SERVICE gateway account. The per-user
// private-directory contract (sole ownership by the caller, a DACL of that
// owner and SYSTEM only) can never hold there, so without this branch the
// gateway of a fresh host refuses to create device.key and exits at its first
// start. Under the service pins the identity directory is validated with the
// managed service trust model instead, plus a check that nobody else can read
// the identity material, and the identity files are created exclusively under
// the runtime DACL they inherit, so the Administrators-run lifecycle can still
// snapshot, restore and re-ACL them during upgrade and repair.
var (
	validateManagedIdentityDirectory = managed.ValidateTrustedServiceRuntimeDir
	validateManagedIdentityFile      = managed.ValidateTrustedServiceRuntimeFilePath
	managedIdentityServiceSID        = managed.WindowsServiceAccountSID
)

// managedServiceIdentityAccount returns the pinned gateway service account when
// this process runs under the managed enterprise service pins. Both pins come
// from the Administrators-owned service registry environment.
func managedServiceIdentityAccount() (string, bool) {
	if !managed.IsManagedEnterprise(managed.PinnedDeploymentMode()) {
		return "", false
	}
	account := strings.TrimSpace(os.Getenv(managed.WindowsServiceAccountEnv))
	return account, account != ""
}

func validateFreshIdentityManagedServiceDirectory(path string) (bool, error) {
	account, ok := managedServiceIdentityAccount()
	if !ok {
		return false, nil
	}
	return true, validateManagedServiceIdentityDirectory(path, account)
}

func validateManagedServiceIdentityDirectory(path, account string) error {
	if err := validateManagedIdentityDirectory(path, "device identity directory", account); err != nil {
		return fmt.Errorf("gateway: validate managed device identity directory %s: %w", path, err)
	}
	if err := rejectUntrustedDeviceIdentityReaders(path, true, account); err != nil {
		return fmt.Errorf("gateway: validate managed device identity directory %s: %w", path, err)
	}
	return nil
}

// createFreshIdentityDirectoryComponent creates one missing directory beneath
// an already validated identity directory. The managed service inherits the
// runtime DACL; everyone else gets a private directory.
func createFreshIdentityDirectoryComponent(path string) error {
	if _, ok := managedServiceIdentityAccount(); ok {
		return os.Mkdir(path, 0o700)
	}
	return safefile.ProtectDirectory(path)
}

// writeFreshIdentityManagedServiceFile publishes one device identity artifact
// for the managed gateway service. The file is created with CREATE_NEW under
// the inherited runtime DACL of its validated directory and then validated
// with the managed service trust model and the reader check.
func writeFreshIdentityManagedServiceFile(path string, data []byte) (bool, error) {
	account, ok := managedServiceIdentityAccount()
	if !ok {
		return false, nil
	}
	if err := validateManagedServiceIdentityDirectory(filepath.Dir(path), account); err != nil {
		return true, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return true, fmt.Errorf("gateway: create managed device identity artifact %s: %w", path, err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return true, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return true, err
	}
	if err := file.Close(); err != nil {
		return true, err
	}
	if err := validateManagedIdentityFile(path, "device identity file", account); err != nil {
		return true, fmt.Errorf("gateway: validate managed device identity artifact %s: %w", path, err)
	}
	if err := rejectUntrustedDeviceIdentityReaders(path, false, account); err != nil {
		return true, fmt.Errorf("gateway: validate managed device identity artifact %s: %w", path, err)
	}
	return true, nil
}

// rejectUntrustedDeviceIdentityReaders fails closed when a principal other
// than SYSTEM, Administrators, TrustedInstaller or the pinned gateway service
// could read identity material at path. For a directory it inspects the ACEs
// that new files inherit; for a file, the ACEs that apply to it.
func rejectUntrustedDeviceIdentityReaders(path string, directory bool, account string) error {
	serviceSID, err := managedIdentityServiceSID(account)
	if err != nil {
		return err
	}
	if serviceSID == nil {
		return fmt.Errorf("managed gateway service SID is unavailable")
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("inspect security descriptor: %w", err)
	}
	if sd == nil {
		return fmt.Errorf("missing security descriptor")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("inspect DACL: %w", err)
	}
	if dacl == nil {
		return fmt.Errorf("a null DACL exposes device identity material")
	}
	const (
		accessAllowedCompoundACEType       = 0x4
		accessAllowedObjectACEType         = 0x5
		accessAllowedCallbackACEType       = 0x9
		accessAllowedCallbackObjectACEType = 0xB
	)
	readLike := windows.ACCESS_MASK(windows.GENERIC_ALL | windows.GENERIC_READ | windows.FILE_READ_DATA)
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return fmt.Errorf("inspect ACE %d: %w", index, err)
		}
		if ace == nil {
			continue
		}
		if directory {
			if ace.Header.AceFlags&windows.OBJECT_INHERIT_ACE == 0 {
				continue
			}
		} else if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		case accessAllowedCompoundACEType, accessAllowedObjectACEType,
			accessAllowedCallbackACEType, accessAllowedCallbackObjectACEType:
			return fmt.Errorf("unsupported allow ACE type 0x%x", ace.Header.AceType)
		default:
			continue
		}
		if ace.Mask&readLike == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		// Creator Owner and Owner Rights resolve to the creating principal,
		// which is this process: the gateway service or an administrator.
		if sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) ||
			sid.IsWellKnown(windows.WinLocalSystemSid) ||
			sid.IsWellKnown(windows.WinCreatorOwnerRightsSid) ||
			(directory && sid.IsWellKnown(windows.WinCreatorOwnerSid)) ||
			sid.Equals(serviceSID) ||
			sid.String() == trustedInstallerSID {
			continue
		}
		return fmt.Errorf("principal %s can read device identity material (access mask 0x%x)", sid.String(), uint32(ace.Mask))
	}
	return nil
}

const trustedInstallerSID = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
