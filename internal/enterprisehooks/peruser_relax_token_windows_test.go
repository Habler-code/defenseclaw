// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"golang.org/x/sys/windows"
)

// The guardian's hardened footprint DACLs. In the owner-view shape the
// read-only OWNER RIGHTS entry removes the owner's implicit WRITE_DAC and the
// owner's own entry does not grant it; it leaves out the Administrators entry
// the real DACL carries, because the elevated test runner would otherwise get
// WRITE_DAC through it and the owner's refusal would not show.
const (
	windowsRelaxTestOwnerViewHardenedFile = "D:P(A;;RC;;;OW)(A;;FA;;;SY)(A;;0x1301bf;;;%s)"
	windowsRelaxTestHardenedFile          = "D:P(A;;RC;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1301bf;;;%s)"
	windowsRelaxTestHardenedDir           = "D:P(A;;RC;;;OW)(A;OICIIO;GA;;;SY)(A;;FA;;;SY)(A;OICIIO;GA;;;BA)(A;;FA;;;BA)(A;OICIIO;DTSDGXGWGR;;;%s)(A;;0x1301ff;;;%s)"
)

func windowsRelaxTestOwner(t *testing.T, path string) *windows.SID {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		t.Fatalf("owner of %s: %v", path, err)
	}
	return owner
}

func windowsRelaxTestSetDACL(t *testing.T, path, sddl string) {
	t.Helper()
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatalf("parse %s: %v", sddl, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil); err != nil {
		t.Fatalf("set DACL of %s: %v", path, err)
	}
}

func windowsRelaxTestFormat(format string, sid *windows.SID) string {
	return strings.ReplaceAll(format, "%s", sid.String())
}

// Republishing a plugin connector's scoped hook token over one an earlier
// reconcile hardened failed for every user (WIN-F18): publication stages the
// new token with the existing file's exact protection and then opens it for
// WRITE_DAC, which the hardened DACL denies the owner. The relax step now
// returns that token to the owner-private shape first, and publication over
// the relaxed token succeeds with nothing but ownership.
func TestRelaxedScopedHookTokenCanBeRepublishedByItsOwner(t *testing.T) {
	oldToken := strings.Repeat("a", 64)
	newToken := strings.Repeat("b", 64)

	// Without the relax step: the owner cannot republish over the hardened shape.
	lockedDir := testenv.PrivateTempDir(t)
	if err := connector.PublishHookAPIToken(lockedDir, "amp", oldToken); err != nil {
		t.Fatalf("seed hook token: %v", err)
	}
	lockedPath, err := connector.HookAPITokenFilePath(lockedDir, "amp")
	if err != nil {
		t.Fatal(err)
	}
	owner := windowsRelaxTestOwner(t, lockedPath)
	windowsRelaxTestSetDACL(t, lockedPath, windowsRelaxTestFormat(windowsRelaxTestOwnerViewHardenedFile, owner))
	err = connector.PublishHookAPIToken(lockedDir, "amp", newToken)
	if err == nil || !strings.Contains(err.Error(), "bound staged file") {
		t.Fatalf("republish over the hardened token: err = %v, want the bound staged file refusal", err)
	}

	// With the relax step (run by the guardian as LocalSystem, which the
	// hardened DACL grants full control; the elevated runner stands in).
	dataDir := testenv.PrivateTempDir(t)
	if err := connector.PublishHookAPIToken(dataDir, "amp", oldToken); err != nil {
		t.Fatalf("seed hook token: %v", err)
	}
	tokenPath, err := connector.HookAPITokenFilePath(dataDir, "amp")
	if err != nil {
		t.Fatal(err)
	}
	windowsRelaxTestSetDACL(t, tokenPath, windowsRelaxTestFormat(windowsRelaxTestHardenedFile, owner))
	target := windowsGenericManagedTarget{home: filepath.Dir(dataDir), sid: owner, dataDir: dataDir}
	changed, err := relaxWindowsStandalonePerUserTokenFile(target, tokenPath)
	if err != nil || !changed {
		t.Fatalf("relax hardened hook token: changed=%v err=%v", changed, err)
	}
	if got := windowsRelaxTestDACL(t, tokenPath); !strings.HasPrefix(got, "D:P") ||
		!strings.HasSuffix(got, "(A;;FA;;;SY)(A;;FA;;;OW)") {
		t.Fatalf("relaxed token DACL = %s, want the owner-private shape", got)
	}
	// The relaxed DACL grants nothing to Administrators, so the runner
	// publishes only as the owner, like the standard user in production.
	if err := connector.PublishHookAPIToken(dataDir, "amp", newToken); err != nil {
		t.Fatalf("republish over the relaxed token: %v", err)
	}
	raw, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != newToken+"\n" {
		t.Fatal("republication did not publish the new token bytes")
	}
	if changed, err := relaxWindowsStandalonePerUserTokenFile(target, tokenPath); err != nil || changed {
		t.Fatalf("relax an owner-private token again: changed=%v err=%v", changed, err)
	}
}

func TestRelaxStandalonePerUserTokenFileLeavesOtherShapesAndRefusesUnsafePaths(t *testing.T) {
	dataDir := testenv.PrivateTempDir(t)
	hooks := filepath.Join(dataDir, "hooks")
	if err := os.MkdirAll(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	home := filepath.Dir(dataDir)
	token := filepath.Join(hooks, ".hook-amp.token")
	if err := os.WriteFile(token, []byte(strings.Repeat("a", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	owner := windowsRelaxTestOwner(t, token)
	target := windowsGenericManagedTarget{home: home, sid: owner, dataDir: dataDir}

	// Not hardened by the guardian: left alone.
	before := windowsRelaxTestDACL(t, token)
	if changed, err := relaxWindowsStandalonePerUserTokenFile(target, token); err != nil || changed {
		t.Fatalf("unhardened token: changed=%v err=%v", changed, err)
	}
	if got := windowsRelaxTestDACL(t, token); got != before {
		t.Fatalf("unhardened token DACL changed: %s -> %s", before, got)
	}

	// Hardened but owned by someone else than the target: left alone.
	windowsRelaxTestSetDACL(t, token, windowsRelaxTestFormat(windowsRelaxTestHardenedFile, owner))
	hardened := windowsRelaxTestDACL(t, token)
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := relaxWindowsStandalonePerUserTokenFile(windowsGenericManagedTarget{home: home, sid: system, dataDir: dataDir}, token); err != nil || changed {
		t.Fatalf("foreign-owned token: changed=%v err=%v", changed, err)
	}
	if got := windowsRelaxTestDACL(t, token); got != hardened {
		t.Fatalf("foreign-owned token DACL changed: %s -> %s", hardened, got)
	}

	// A second hard link is refused and the DACL stays hardened.
	link := filepath.Join(hooks, "linked.token")
	if err := os.Link(token, link); err != nil {
		t.Fatal(err)
	}
	if _, err := relaxWindowsStandalonePerUserTokenFile(target, token); err == nil || !strings.Contains(err.Error(), "hard links") {
		t.Fatalf("hard-linked token: err = %v, want a hard-link refusal", err)
	}
	if got := windowsRelaxTestDACL(t, token); got != hardened {
		t.Fatalf("hard-linked token DACL changed: %s -> %s", hardened, got)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}

	// Missing is a no-op; a directory or a path outside the home is refused.
	if changed, err := relaxWindowsStandalonePerUserTokenFile(target, filepath.Join(hooks, ".hook-opencode.token")); err != nil || changed {
		t.Fatalf("missing token: changed=%v err=%v", changed, err)
	}
	dirToken := filepath.Join(hooks, ".hook-devin.token")
	if err := os.Mkdir(dirToken, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := relaxWindowsStandalonePerUserTokenFile(target, dirToken); err == nil {
		t.Fatal("a directory at the token path was accepted")
	}
	if _, err := relaxWindowsStandalonePerUserTokenFile(windowsGenericManagedTarget{home: hooks, sid: owner, dataDir: dataDir}, filepath.Join(dataDir, "outside.token")); err == nil {
		t.Fatal("a token outside the user home was accepted")
	}
}

// Hermes setup re-protects <data dir> itself with safefile.ProtectDirectory
// under the user's token. Hardening after any earlier connector for that user
// leaves <data dir> without the owner's WRITE_DAC, so Hermes setup failed with
// "create managed backup dir <home>\.defenseclaw: Access is denied" for every
// user with Hermes and another agent, and the install never reached coverage
// (WIN-F19). The relax step now includes <data dir> for Hermes only.
func TestRelaxStandalonePerUserFootprintIncludesHermesDataDir(t *testing.T) {
	// The elevated test runner is not refused by ProtectDirectory on the
	// hardened shape, so the standard user's refusal is not reproducible here;
	// the test pins that the relax step gives the owner WRITE_DAC (OWNER RIGHTS
	// full control) on the data dir before Hermes setup runs.
	owner := currentWindowsTestSID(t)
	for _, tc := range []struct {
		name      string
		conn      connector.Connector
		wantRelax bool
	}{
		{name: "hermes", conn: connector.NewHermesConnector(), wantRelax: true},
		{name: "opencode", conn: connector.NewOpenCodeConnector(), wantRelax: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := testenv.PrivateTempDir(t)
			dataDir := filepath.Join(home, ".defenseclaw")
			if err := os.Mkdir(dataDir, 0o700); err != nil {
				t.Fatal(err)
			}
			setWindowsTestPathExactOwner(t, dataDir, owner)
			windowsRelaxTestSetDACL(t, dataDir, windowsRelaxTestFormat(windowsRelaxTestHardenedDir, owner))
			hardened := windowsRelaxTestDACL(t, dataDir)
			target := windowsGenericManagedTarget{home: home, sid: owner, dataDir: dataDir, conn: tc.conn}
			relaxed, err := relaxWindowsStandalonePerUserFootprintForSetup(target, nil, connector.AgentPaths{})
			if err != nil {
				t.Fatalf("relax footprint: %v", err)
			}
			got := windowsRelaxTestDACL(t, dataDir)
			if !tc.wantRelax {
				if slices.Contains(relaxed, dataDir) || got != hardened {
					t.Fatalf("%s: data dir relaxed (%v): %s -> %s", tc.name, relaxed, hardened, got)
				}
				return
			}
			if !slices.Contains(relaxed, dataDir) {
				t.Fatalf("hermes: relaxed = %v, want the data dir", relaxed)
			}
			if !strings.HasPrefix(got, "D:P") || !strings.HasSuffix(got, "(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)") {
				t.Fatalf("hermes: relaxed data dir DACL = %s, want the owner-private shape", got)
			}
			// What Hermes setup does next, now with the owner's WRITE_DAC.
			if err := safefile.ProtectDirectory(dataDir); err != nil {
				t.Fatalf("hermes: ProtectDirectory on the relaxed data dir: %v", err)
			}
		})
	}
}

// A setup that fails after relaxing a file must give that file the canonical
// managed DACL back, as hardening would; restoring it as a directory refused it.
func TestRestoreRelaxedPerUserFootprintReturnsCanonicalFileDACL(t *testing.T) {
	stubWindowsAuthorizedRepairIdentityChecks(t)
	fixture := newWindowsGenericCodexFixture(t)
	target := windowsGenericManagedTarget{home: fixture.home, sid: fixture.targetSID}
	if err := validateWindowsUserPathElement(fixture.config, fixture.targetSID, false, true, true); err != nil {
		t.Fatalf("fixture file is not canonical: %v", err)
	}
	changed, err := relaxWindowsStandalonePerUserTokenFile(target, fixture.config)
	if err != nil || !changed {
		t.Fatalf("relax canonical file: changed=%v err=%v", changed, err)
	}
	if err := validateWindowsUserPathElement(fixture.config, fixture.targetSID, false, true, true); err == nil {
		t.Fatal("relaxed file still validates as canonical")
	}
	if err := restoreWindowsRelaxedPerUserDirectories(target, []string{fixture.config}); err != nil {
		t.Fatalf("restore relaxed file: %v", err)
	}
	if err := validateWindowsUserPathElement(fixture.config, fixture.targetSID, false, true, true); err != nil {
		t.Fatalf("restored file is not canonical: %v", err)
	}
}
