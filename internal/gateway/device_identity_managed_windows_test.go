// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// managedRuntimeFixtureSDDL mirrors the installer's RuntimeDirectory ACL:
// SYSTEM and Administrators full control and Modify (0x1301bf) for the exact
// gateway service SID, inherited by files and subdirectories, protected.
func managedRuntimeFixtureSDDL(serviceSID *windows.SID, extraACEs string) string {
	return "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;" + serviceSID.String() + ")" + extraACEs
}

func applyDeviceIdentityFixtureSecurity(t *testing.T, path, sddl string, setOwner bool) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("parse fixture descriptor %q: %v", sddl, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("fixture DACL: %v", err)
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	var owner *windows.SID
	if setOwner {
		owner, _, err = sd.Owner()
		if err != nil || owner == nil {
			t.Fatalf("fixture owner: %v", err)
		}
		info |= windows.OWNER_SECURITY_INFORMATION
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, info, owner, nil, dacl, nil); err != nil {
		t.Fatalf("apply fixture security to %s: %v", path, err)
	}
}

func currentDeviceIdentityTestUser(t *testing.T) *windows.SID {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("resolve current token user: %v", err)
	}
	sid, err := user.User.Sid.Copy()
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

// stubManagedIdentityTrust lets a temp directory stand in for the managed
// runtime tree: the Administrators-owned ancestor chain of the real tree
// cannot be built without elevation, so the ancestor walk is recorded rather
// than performed. The reader check still runs against the real DACL.
func stubManagedIdentityTrust(t *testing.T, account string, serviceSID *windows.SID) *[]string {
	t.Helper()
	calls := []string{}
	previousDirectory := validateManagedIdentityDirectory
	previousFile := validateManagedIdentityFile
	previousSID := managedIdentityServiceSID
	validateManagedIdentityDirectory = func(path, _ string, gotAccount string) error {
		if gotAccount != account {
			t.Fatalf("directory validator account = %q, want %q", gotAccount, account)
		}
		calls = append(calls, "dir:"+filepath.Base(path))
		return nil
	}
	validateManagedIdentityFile = func(path, _ string, gotAccount string) error {
		if gotAccount != account {
			t.Fatalf("file validator account = %q, want %q", gotAccount, account)
		}
		calls = append(calls, "file:"+filepath.Base(path))
		return nil
	}
	managedIdentityServiceSID = func(gotAccount string) (*windows.SID, error) {
		if gotAccount != account {
			t.Fatalf("service SID account = %q, want %q", gotAccount, account)
		}
		return serviceSID, nil
	}
	t.Cleanup(func() {
		validateManagedIdentityDirectory = previousDirectory
		validateManagedIdentityFile = previousFile
		managedIdentityServiceSID = previousSID
	})
	return &calls
}

func setManagedServiceIdentityPins(t *testing.T, account string) {
	t.Helper()
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	t.Setenv(managed.WindowsServiceAccountEnv, account)
}

func deviceIdentityArtifacts(dataDir string) []string {
	keyFile := filepath.Join(dataDir, "device.key")
	return []string{
		keyFile,
		keyFile + ".provenance",
		filepath.Join(dataDir, deviceProvenanceSecretName),
	}
}

// fileAllAccess is FILE_ALL_ACCESS, the mapped form of the FA SDDL right.
const fileAllAccess windows.ACCESS_MASK = 0x001F01FF

// requireAdministratorsFullControl proves the Administrators-run lifecycle
// can open and re-ACL the artifact, which a private owner+SYSTEM DACL denies.
func requireAdministratorsFullControl(t *testing.T, path string) {
	t.Helper()
	extended, err := winpath.Extended(path)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read %s security: %v", path, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("read %s DACL: %v", path, err)
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			t.Fatal(err)
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) &&
			(ace.Mask&fileAllAccess == fileAllAccess || ace.Mask&windows.GENERIC_ALL != 0) {
			return
		}
	}
	t.Fatalf("%s does not carry the runtime Administrators full-control ACE, so the lifecycle cannot adopt it", path)
}

func TestLoadOrCreateIdentityManagedServiceCreatesIdentityInRuntimeDirectory(t *testing.T) {
	const account = `NT SERVICE\DefenseClawGateway`
	serviceSID := currentDeviceIdentityTestUser(t)
	dataDir := filepath.Join(testenv.PrivateTempDir(t), "runtime")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	applyDeviceIdentityFixtureSecurity(t, dataDir, managedRuntimeFixtureSDDL(serviceSID, ""), false)
	setManagedServiceIdentityPins(t, account)
	calls := stubManagedIdentityTrust(t, account, serviceSID)

	identity, err := LoadOrCreateIdentity(filepath.Join(dataDir, "device.key"), dataDir)
	if err != nil {
		t.Fatalf("managed gateway service could not create its device identity in the runtime directory: %v", err)
	}
	for _, artifact := range deviceIdentityArtifacts(dataDir) {
		if _, err := os.Lstat(artifact); err != nil {
			t.Fatalf("identity artifact %s: %v", artifact, err)
		}
		requireAdministratorsFullControl(t, artifact)
	}
	var sawDirectory, sawFile bool
	for _, call := range *calls {
		sawDirectory = sawDirectory || strings.HasPrefix(call, "dir:")
		sawFile = sawFile || strings.HasPrefix(call, "file:")
	}
	if !sawDirectory || !sawFile {
		t.Fatalf("managed trust validators were not consulted: %v", *calls)
	}
	reloaded, err := LoadOrCreateIdentity(filepath.Join(dataDir, "device.key"), dataDir)
	if err != nil || reloaded.DeviceID != identity.DeviceID {
		t.Fatalf("reload = %v, %v; want device %s", reloaded, err, identity.DeviceID)
	}
}

func TestLoadOrCreateIdentityManagedServiceNestedKeyDirectoryInheritsRuntimeDACL(t *testing.T) {
	const account = `NT SERVICE\DefenseClawGateway`
	serviceSID := currentDeviceIdentityTestUser(t)
	dataDir := filepath.Join(testenv.PrivateTempDir(t), "runtime")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	applyDeviceIdentityFixtureSecurity(t, dataDir, managedRuntimeFixtureSDDL(serviceSID, ""), false)
	setManagedServiceIdentityPins(t, account)
	stubManagedIdentityTrust(t, account, serviceSID)

	keyFile := filepath.Join(dataDir, "identity", "device.key")
	if _, err := LoadOrCreateIdentity(keyFile, dataDir); err != nil {
		t.Fatalf("nested managed device identity: %v", err)
	}
	for _, path := range []string{filepath.Dir(keyFile), keyFile, keyFile + ".provenance"} {
		requireAdministratorsFullControl(t, path)
	}
}

func TestLoadOrCreateIdentityManagedServiceRefusesReadableRuntimeDirectory(t *testing.T) {
	const account = `NT SERVICE\DefenseClawGateway`
	serviceSID := currentDeviceIdentityTestUser(t)
	for name, extra := range map[string]string{
		"users_read":          "(A;OICI;FR;;;BU)",
		"everyone_generic":    "(A;OI;GR;;;WD)",
		"authenticated_files": "(A;OIIO;FR;;;AU)",
	} {
		t.Run(name, func(t *testing.T) {
			dataDir := filepath.Join(testenv.PrivateTempDir(t), "runtime")
			if err := os.Mkdir(dataDir, 0o700); err != nil {
				t.Fatal(err)
			}
			applyDeviceIdentityFixtureSecurity(t, dataDir, managedRuntimeFixtureSDDL(serviceSID, extra), false)
			setManagedServiceIdentityPins(t, account)
			stubManagedIdentityTrust(t, account, serviceSID)

			_, err := LoadOrCreateIdentity(filepath.Join(dataDir, "device.key"), dataDir)
			if err == nil || !strings.Contains(err.Error(), "can read device identity material") {
				t.Fatalf("readable runtime directory error = %v, want a reader refusal", err)
			}
			for _, artifact := range deviceIdentityArtifacts(dataDir) {
				if _, statErr := os.Lstat(artifact); !os.IsNotExist(statErr) {
					t.Fatalf("refused identity creation left %s behind: %v", artifact, statErr)
				}
			}
		})
	}
}

func TestLoadOrCreateIdentityRuntimeDirectoryNeedsBothServicePins(t *testing.T) {
	serviceSID := currentDeviceIdentityTestUser(t)
	for name, pins := range map[string][2]string{
		"no_deployment_mode": {"", `NT SERVICE\DefenseClawGateway`},
		"no_service_account": {managed.DeploymentModeManagedEnterprise, ""},
	} {
		t.Run(name, func(t *testing.T) {
			dataDir := filepath.Join(testenv.PrivateTempDir(t), "runtime")
			if err := os.Mkdir(dataDir, 0o700); err != nil {
				t.Fatal(err)
			}
			applyDeviceIdentityFixtureSecurity(t, dataDir, managedRuntimeFixtureSDDL(serviceSID, ""), false)
			t.Setenv(managed.DeploymentModeEnv, pins[0])
			t.Setenv(managed.WindowsServiceAccountEnv, pins[1])

			_, err := LoadOrCreateIdentity(filepath.Join(dataDir, "device.key"), dataDir)
			if err == nil || !strings.Contains(err.Error(), "must already be private") {
				t.Fatalf("unpinned runtime-shaped directory error = %v, want the private-directory refusal", err)
			}
		})
	}
}

// TestLoadOrCreateIdentityManagedServiceRealRuntimeTrust runs the unstubbed
// managed trust model against a ProgramData tree shaped like the Secure Client
// runtime directory. A real NT SERVICE account stands in for the gateway.
func TestLoadOrCreateIdentityManagedServiceRealRuntimeTrust(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("an Administrators-owned ProgramData fixture requires an elevated process token")
	}
	const account = `NT SERVICE\EventLog`
	serviceSID, err := managed.WindowsServiceAccountSID(account)
	if err != nil {
		t.Skipf("resolve %s: %v", account, err)
	}
	programData, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, windows.KF_FLAG_DEFAULT)
	if err != nil {
		t.Fatalf("resolve ProgramData: %v", err)
	}
	root, err := os.MkdirTemp(programData, "DefenseClaw-device-identity-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	applyDeviceIdentityFixtureSecurity(t, root, "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)", true)
	dataDir := filepath.Join(root, "runtime")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	applyDeviceIdentityFixtureSecurity(t, dataDir, "O:BA"+managedRuntimeFixtureSDDL(serviceSID, ""), true)
	setManagedServiceIdentityPins(t, account)

	identity, err := LoadOrCreateIdentity(filepath.Join(dataDir, "device.key"), dataDir)
	if err != nil {
		t.Fatalf("device identity in a Secure Client shaped runtime directory: %v", err)
	}
	for _, artifact := range deviceIdentityArtifacts(dataDir) {
		requireAdministratorsFullControl(t, artifact)
		if err := managed.ValidateTrustedServiceRuntimeFilePath(artifact, "device identity file", account); err != nil {
			t.Fatalf("artifact %s outside the managed trust model: %v", artifact, err)
		}
	}
	reloaded, err := LoadOrCreateIdentity(filepath.Join(dataDir, "device.key"), dataDir)
	if err != nil || reloaded.DeviceID != identity.DeviceID {
		t.Fatalf("reload = %v, %v; want device %s", reloaded, err, identity.DeviceID)
	}
}
