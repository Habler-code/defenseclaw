// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"errors"
	"net"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

const (
	testProgramFilesX86 = `C:\Program Files (x86)`
	testProgramFiles    = `C:\Program Files`
	testGUIImage        = `C:\Program Files (x86)\Cisco\Cisco Secure Client\UI\csc_ui.exe`
	testGUIKernelImage  = `\Device\HarddiskVolume3\Program Files (x86)\Cisco\Cisco Secure Client\UI\csc_ui.exe`
	testCiscoSigner     = "Cisco Systems, Inc."
)

// testDriveDevice stands in for QueryDosDevice.
func testDriveDevice(drive string) (string, error) {
	switch drive {
	case "C:":
		return `\Device\HarddiskVolume3`, nil
	case "D:":
		return `\Device\HarddiskVolume4`, nil
	}
	return "", errors.New("no such drive")
}

func testWindowsPeerPolicy(t *testing.T) windowsPeerPolicy {
	t.Helper()
	policy, err := newWindowsPeerPolicy(
		[]string{testProgramFilesX86, testProgramFiles},
		[]string{`UI\csc_ui.exe`},
		[]string{testCiscoSigner},
		testDriveDevice,
	)
	if err != nil {
		t.Fatalf("newWindowsPeerPolicy: %v", err)
	}
	return policy
}

type fakeWindowsPeerImage struct {
	finalPath string
	signer    windowsImageSigner
	signerErr error

	mu       sync.Mutex
	verified bool
	closed   bool
}

func (f *fakeWindowsPeerImage) FinalPath() string { return f.finalPath }

func (f *fakeWindowsPeerImage) VerifySigner() (windowsImageSigner, error) {
	f.mu.Lock()
	f.verified = true
	f.mu.Unlock()
	return f.signer, f.signerErr
}

func (f *fakeWindowsPeerImage) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return nil
}

type fakeWindowsPeer struct {
	pid        uint32
	pidErr     error
	process    windowsPeerProcess
	processErr error
	image      *fakeWindowsPeerImage
	imageErr   error
	// shortNames, when non-nil, turns on the fake shortName resolver:
	// the 8.3 name each path holds, keyed by windowsPathKey, with ""
	// for paths that have none. shortNameErr makes every lookup fail.
	shortNames   map[string]string
	shortNameErr error

	mu           sync.Mutex
	openedPath   []string
	shortLookups []string
}

func (f *fakeWindowsPeer) opened() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.openedPath...)
}

var testProcessCreatedAt = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

func genuineWindowsPeer() *fakeWindowsPeer {
	return &fakeWindowsPeer{
		pid: 4242,
		process: windowsPeerProcess{
			ImagePath: testGUIKernelImage,
			SessionID: 1,
			CreatedAt: testProcessCreatedAt,
		},
		image: &fakeWindowsPeerImage{
			finalPath: testGUIImage,
			signer: windowsImageSigner{
				CommonName:    testCiscoSigner,
				Organizations: []string{testCiscoSigner},
			},
		},
	}
}

// setShortNames replaces the names the fake shortName resolver reports,
// as if the volume's 8.3 names changed between two connections.
func (f *fakeWindowsPeer) setShortNames(names map[string]string, err error) {
	f.mu.Lock()
	f.shortNames, f.shortNameErr = names, err
	f.mu.Unlock()
}

func (f *fakeWindowsPeer) lookedUp() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.shortLookups...)
}

func (f *fakeWindowsPeer) resolvers() windowsPeerResolvers {
	resolvers := windowsPeerResolvers{
		peerPID: func(net.Conn) (uint32, error) { return f.pid, f.pidErr },
		process: func(pid uint32) (windowsPeerProcess, error) {
			if pid != f.pid {
				return windowsPeerProcess{}, errors.New("unexpected pid")
			}
			return f.process, f.processErr
		},
		openImage: func(path string) (windowsPeerImage, error) {
			f.mu.Lock()
			f.openedPath = append(f.openedPath, path)
			f.mu.Unlock()
			if f.imageErr != nil {
				return nil, f.imageErr
			}
			return f.image, nil
		},
	}
	f.mu.Lock()
	enabled := f.shortNames != nil || f.shortNameErr != nil
	f.mu.Unlock()
	if enabled {
		resolvers.shortName = func(path string) (string, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.shortLookups = append(f.shortLookups, path)
			if f.shortNameErr != nil {
				return "", f.shortNameErr
			}
			return f.shortNames[windowsPathKey(path)], nil
		}
	}
	return resolvers
}

func authenticateFake(t *testing.T, peer *fakeWindowsPeer) (windowsPeerIdentity, string) {
	t.Helper()
	listener, err := newWindowsPeerAuthListener(stubListener{}, testWindowsPeerPolicy(t), peer.resolvers(), nil)
	if err != nil {
		t.Fatalf("newWindowsPeerAuthListener: %v", err)
	}
	return listener.authenticate(nil)
}

type stubListener struct{}

func (stubListener) Accept() (net.Conn, error) { return nil, errors.New("stub") }
func (stubListener) Close() error              { return nil }
func (stubListener) Addr() net.Addr            { return &net.UnixAddr{Name: "stub", Net: "unix"} }

func TestWindowsPeerAuthAdmitsGenuineSecureClientGUI(t *testing.T) {
	peer := genuineWindowsPeer()
	id, reason := authenticateFake(t, peer)
	if reason != "" {
		t.Fatalf("genuine Secure Client GUI rejected: %s", reason)
	}
	if id.PID != 4242 || id.SessionID != 1 || id.ImagePath != testGUIImage || id.Signer != testCiscoSigner {
		t.Fatalf("identity = %+v", id)
	}
	if !peer.image.verified || !peer.image.closed {
		t.Fatalf("image verified=%v closed=%v, want both", peer.image.verified, peer.image.closed)
	}
	// The file opened is the policy's own path, not the kernel string.
	if opened := peer.opened(); len(opened) != 1 || opened[0] != testGUIImage {
		t.Fatalf("opened = %q, want [%q]", opened, testGUIImage)
	}
}

func TestWindowsPeerAuthAdmitsGUIFromEitherProgramFilesRootCaseInsensitively(t *testing.T) {
	for _, tc := range []struct{ kernel, final string }{
		{
			`\Device\HarddiskVolume3\Program Files\Cisco\Cisco Secure Client\UI\csc_ui.exe`,
			`C:\Program Files\Cisco\Cisco Secure Client\UI\csc_ui.exe`,
		},
		{
			`\device\harddiskvolume3\program files (x86)\cisco\cisco secure client\ui\CSC_UI.EXE`,
			`c:\program files (x86)\cisco\cisco secure client\ui\CSC_UI.EXE`,
		},
	} {
		peer := genuineWindowsPeer()
		peer.process.ImagePath = tc.kernel
		peer.image.finalPath = tc.final
		if _, reason := authenticateFake(t, peer); reason != "" {
			t.Errorf("%s rejected: %s", tc.kernel, reason)
		}
	}
}

// TestWindowsPeerAuthToleratesWallClockStepBack admits a GUI whose
// recorded creation time is later than the current wall clock, as it
// is after the system clock is stepped backwards.
func TestWindowsPeerAuthToleratesWallClockStepBack(t *testing.T) {
	peer := genuineWindowsPeer()
	peer.process.CreatedAt = time.Now().Add(time.Hour)
	if _, reason := authenticateFake(t, peer); reason != "" {
		t.Fatalf("GUI rejected after a clock step: %s", reason)
	}
}

// TestWindowsPeerAuthDoesNotOpenImagesOutsideThePolicy checks that a
// process whose image name is not an allowed executable is refused by
// string comparison alone: the gateway opens nothing on its behalf.
func TestWindowsPeerAuthDoesNotOpenImagesOutsideThePolicy(t *testing.T) {
	for _, kernelPath := range []string{
		`\Device\Mup\server\share\Cisco\Cisco Secure Client\UI\csc_ui.exe`,
		`\Device\Mup\;LanmanRedirector\server\share\csc_ui.exe`,
		`\Device\LanmanRedirector\server\share\Program Files (x86)\Cisco\Cisco Secure Client\UI\csc_ui.exe`,
		`\Device\WebDavRedirector\host\DavWWWRoot\csc_ui.exe`,
		`\Device\HarddiskVolume3\Users\alice\Downloads\csc_ui.exe`,
		`\Device\HarddiskVolume9\Program Files (x86)\Cisco\Cisco Secure Client\UI\csc_ui.exe`,
		`\Device\HarddiskVolume3\Program Files (x86)\Cisco\Cisco Secure Client\UI\..\UI\csc_ui.exe`,
		`\Device\HarddiskVolume3\PROGRA~2\Cisco\CISCOS~1\UI\csc_ui.exe`,
		`\\?\GLOBALROOT\Device\HarddiskVolume3\Program Files (x86)\Cisco\Cisco Secure Client\UI\csc_ui.exe`,
		`\\server\share\csc_ui.exe`,
		testGUIImage,
		"",
	} {
		peer := genuineWindowsPeer()
		peer.process.ImagePath = kernelPath
		_, reason := authenticateFake(t, peer)
		if !strings.Contains(reason, "not an allowed Secure Client GUI executable") {
			t.Errorf("%q: reason = %q", kernelPath, reason)
		}
		if opened := peer.opened(); len(opened) != 0 {
			t.Errorf("%q: gateway opened %q", kernelPath, opened)
		}
	}
}

// testGUIShortKernelImage is testGUIKernelImage written with the 8.3
// names genuineShortNames reports, as the kernel records it when the
// GUI is started through C:\PROGRA~2\Cisco\CISCOS~1\UI\csc_ui.exe.
const testGUIShortKernelImage = `\Device\HarddiskVolume3\PROGRA~2\Cisco\CISCOS~1\UI\csc_ui.exe`

// genuineShortNames is the fake volume's 8.3 names for the allowed
// paths. Paths it does not list have no short name.
func genuineShortNames() map[string]string {
	return map[string]string{
		windowsPathKey(testProgramFilesX86):                                              "PROGRA~2",
		windowsPathKey(testProgramFiles):                                                 "PROGRA~1",
		windowsPathKey(testProgramFilesX86 + `\Cisco\Cisco Secure Client`):               "CISCOS~1",
		windowsPathKey(testProgramFiles + `\Cisco\Cisco Secure Client`):                  "CISCOS~1",
		windowsPathKey(testProgramFilesX86 + `\Cisco\Cisco Secure Client\UI\csc_ui.exe`): "CSC_UI~1.EXE",
	}
}

// requireLookupsOfPolicyPaths fails the test unless every short-name
// lookup named the policy's own paths: an allowed executable or a
// directory above it, never a path taken from the peer.
func requireLookupsOfPolicyPaths(t *testing.T, label string, policy windowsPeerPolicy, lookups []string) {
	t.Helper()
	allowed := make(map[string]struct{})
	for _, image := range policy.images {
		path := image.drivePath
		for len(path) > len(`C:\`) {
			allowed[windowsPathKey(path)] = struct{}{}
			path = path[:strings.LastIndexByte(path, '\\')]
		}
	}
	for _, lookup := range lookups {
		if _, ok := allowed[windowsPathKey(lookup)]; !ok {
			t.Errorf("%s: short name looked up for %q, which is not a policy path", label, lookup)
		}
	}
}

// TestWindowsPeerAuthAdmitsGUILaunchedThroughCurrentShortNames covers a
// GUI started through an 8.3 short path. The kernel records the short
// elements; each must be the short name the allowed element holds, and
// the file opened is still the policy's long path.
func TestWindowsPeerAuthAdmitsGUILaunchedThroughCurrentShortNames(t *testing.T) {
	x64GUI := testProgramFiles + `\Cisco\Cisco Secure Client\UI\csc_ui.exe`
	for _, tc := range []struct{ kernel, drive string }{
		{testGUIShortKernelImage, testGUIImage},
		{`\device\harddiskvolume3\progra~2\cisco\ciscos~1\ui\csc_ui.exe`, testGUIImage},
		{`\Device\HarddiskVolume3\Program Files (x86)\Cisco\CISCOS~1\UI\csc_ui.exe`, testGUIImage},
		{`\Device\HarddiskVolume3\PROGRA~2\Cisco\Cisco Secure Client\UI\csc_ui.exe`, testGUIImage},
		{`\Device\HarddiskVolume3\PROGRA~2\Cisco\CISCOS~1\UI\CSC_UI~1.EXE`, testGUIImage},
		{`\Device\HarddiskVolume3\PROGRA~1\Cisco\CISCOS~1\UI\csc_ui.exe`, x64GUI},
	} {
		peer := genuineWindowsPeer()
		peer.process.ImagePath = tc.kernel
		peer.image.finalPath = tc.drive
		peer.shortNames = genuineShortNames()
		id, reason := authenticateFake(t, peer)
		if reason != "" {
			t.Errorf("%q rejected: %s", tc.kernel, reason)
			continue
		}
		if opened := peer.opened(); len(opened) != 1 || opened[0] != tc.drive {
			t.Errorf("%q: opened = %q, want [%q]", tc.kernel, opened, tc.drive)
		}
		if id.ImagePath != tc.drive || !peer.image.verified {
			t.Errorf("%q: identity %+v, verified=%v", tc.kernel, id, peer.image.verified)
		}
		requireLookupsOfPolicyPaths(t, tc.kernel, testWindowsPeerPolicy(t), peer.lookedUp())
	}
}

// TestWindowsPeerAuthRefusesTildeNamesThatAreNotTheAllowedPath checks
// that a "~" element is accepted only as the current short name of the
// allowed element in the same place, and that the gateway opens nothing
// for any other name.
func TestWindowsPeerAuthRefusesTildeNamesThatAreNotTheAllowedPath(t *testing.T) {
	kernelPaths := []string{
		// A short name the allowed directory does not hold, such as a
		// standard user's own C:\Program Files (x87) (PROGRA~3).
		`\Device\HarddiskVolume3\PROGRA~3\Cisco\CISCOS~1\UI\csc_ui.exe`,
		`\Device\HarddiskVolume3\PROGRA~2\Cisco\CISCOS~2\UI\csc_ui.exe`,
		// The 64-bit GUI has no short name on this volume.
		`\Device\HarddiskVolume3\PROGRA~1\Cisco\CISCOS~1\UI\CSC_UI~1.EXE`,
		// Real short names, but of other elements.
		`\Device\HarddiskVolume3\CISCOS~1\Cisco\PROGRA~2\UI\csc_ui.exe`,
		`\Device\HarddiskVolume3\PROGRA~2\Cisco\PROGRA~2\UI\csc_ui.exe`,
		// Element counts, devices and suffixes that differ.
		`\Device\HarddiskVolume3\PROGRA~2\Cisco\CISCOS~1\csc_ui.exe`,
		`\Device\HarddiskVolume3\PROGRA~2\Cisco\CISCOS~1\UI\UI\csc_ui.exe`,
		`\Device\HarddiskVolume3\PROGRA~2\Cisco\CISCOS~1\UI\..\UI\csc_ui.exe`,
		`\Device\HarddiskVolume3\PROGRA~2\\Cisco\CISCOS~1\UI\csc_ui.exe`,
		`\Device\HarddiskVolume3\Users\alice\PROGRA~2\Cisco\CISCOS~1\UI\csc_ui.exe`,
		`\Device\HarddiskVolume4\PROGRA~2\Cisco\CISCOS~1\UI\csc_ui.exe`,
		`\Device\HarddiskVolume33\PROGRA~2\Cisco\CISCOS~1\UI\csc_ui.exe`,
		`\\?\GLOBALROOT\Device\HarddiskVolume3\PROGRA~2\Cisco\CISCOS~1\UI\csc_ui.exe`,
		`\Device\HarddiskVolume3\PROGRA~2 \Cisco\CISCOS~1\UI\csc_ui.exe`,
		`\Device\HarddiskVolume3\PROGRA~2\Cisco\CISCOS~1\UI\csc_ui.exe:x`,
		`\Device\HarddiskVolume3\PROGRA~2\Cisco\CISCOS~1\UI\csc_ui.exe\`,
		`\Device\HarddiskVolume3\PROGRA~2`,
		`\Device\HarddiskVolume3\~`,
		`\Device\HarddiskVolume3\PROGRA~2\Cisco\CISCOS~1\UI\csc_ui` + "\ufffd" + `.exe`,
		"\\Device\\HarddiskVolume3\\PROGRA~2\\Cisco\\CISCOS~1\\UI\\csc_ui\xff.exe",
		`C:\PROGRA~2\Cisco\CISCOS~1\UI\csc_ui.exe`,
	}
	// Unicode-fold look-alikes of the short form, like those of the long
	// form in TestWindowsPeerAuthRejectsUnicodeFoldLookAlikes.
	kernelPaths = append(kernelPaths, unicodeFoldVariants(t, testGUIShortKernelImage)...)
	policy := testWindowsPeerPolicy(t)
	for _, kernelPath := range kernelPaths {
		peer := genuineWindowsPeer()
		peer.process.ImagePath = kernelPath
		peer.shortNames = genuineShortNames()
		_, reason := authenticateFake(t, peer)
		if !strings.Contains(reason, "not an allowed Secure Client GUI executable") {
			t.Errorf("%q: reason = %q", kernelPath, reason)
		}
		if opened := peer.opened(); len(opened) != 0 {
			t.Errorf("%q: gateway opened %q", kernelPath, opened)
		}
		requireLookupsOfPolicyPaths(t, kernelPath, policy, peer.lookedUp())
	}
}

// TestWindowsPeerAuthReadsShortNamesWhenThePeerConnects checks that the
// short names come from the volume at each connection, not from when
// the listener was built. After fsutil 8dot3name strip removes
// PROGRA~2, a standard user may create C:\PROGRA~2 in the drive root,
// so a remembered short name would admit a process started from there.
func TestWindowsPeerAuthReadsShortNamesWhenThePeerConnects(t *testing.T) {
	peer := genuineWindowsPeer()
	peer.process.ImagePath = testGUIShortKernelImage
	peer.shortNames = genuineShortNames()
	listener, err := newWindowsPeerAuthListener(stubListener{}, testWindowsPeerPolicy(t), peer.resolvers(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, reason := listener.authenticate(nil); reason != "" {
		t.Fatalf("GUI started through current short names rejected: %s", reason)
	}

	stripped := genuineShortNames()
	delete(stripped, windowsPathKey(testProgramFilesX86))
	peer.setShortNames(stripped, nil)
	if _, reason := listener.authenticate(nil); !strings.Contains(reason, "not an allowed Secure Client GUI executable") {
		t.Fatalf("name with a removed short name: reason = %q", reason)
	}

	peer.setShortNames(nil, errors.New("access denied"))
	if _, reason := listener.authenticate(nil); !strings.Contains(reason, "not an allowed Secure Client GUI executable") {
		t.Fatalf("short-name lookup failure: reason = %q", reason)
	}
	if opened := peer.opened(); len(opened) != 1 {
		t.Fatalf("opened = %q, want only the first, admitted connection", opened)
	}
}

// TestWindowsPeerAuthLooksUpShortNamesOnlyForTildeElements checks that
// an image name without "~" costs no filesystem lookup, and that a
// "~" name looks up only the allowed elements it differs from.
func TestWindowsPeerAuthLooksUpShortNamesOnlyForTildeElements(t *testing.T) {
	for _, kernelPath := range []string{
		`\Device\HarddiskVolume3\Users\alice\Downloads\csc_ui.exe`,
		`\Device\HarddiskVolume3\Program File` + "\u017f" + ` (x86)\Cisco\Cisco Secure Client\UI\csc_ui.exe`,
		testGUIKernelImage,
		`\Device\HarddiskVolume4\PROGRA~2\Cisco\CISCOS~1\UI\csc_ui.exe`,
		`\Device\HarddiskVolume3\PROGRA~2\Cisco\CISCOS~1\UI\UI\csc_ui.exe`,
		`\Device\HarddiskVolume3\Programs\Cisco\CISCOS~1\UI\csc_ui.exe`,
	} {
		peer := genuineWindowsPeer()
		peer.process.ImagePath = kernelPath
		peer.shortNames = genuineShortNames()
		_, _ = authenticateFake(t, peer)
		if lookups := peer.lookedUp(); len(lookups) != 0 {
			t.Errorf("%q: looked up %q", kernelPath, lookups)
		}
	}

	peer := genuineWindowsPeer()
	peer.process.ImagePath = `\Device\HarddiskVolume3\Program Files (x86)\Cisco\CISCOS~1\UI\csc_ui.exe`
	peer.shortNames = genuineShortNames()
	if _, reason := authenticateFake(t, peer); reason != "" {
		t.Fatalf("rejected: %s", reason)
	}
	want := testProgramFilesX86 + `\Cisco\Cisco Secure Client`
	if lookups := peer.lookedUp(); len(lookups) != 1 || lookups[0] != want {
		t.Fatalf("lookups = %q, want [%q]", lookups, want)
	}
}

// TestWindowsPeerAuthExplainsShortNameLaunchRefusal covers a "~" image
// name that is refused: short-name matching is off, a short name is no
// longer current, or the lookup failed. The comparison refuses it
// without opening anything, and the logged reason must say why, since
// the refused process may be the genuine GUI.
func TestWindowsPeerAuthExplainsShortNameLaunchRefusal(t *testing.T) {
	stale := genuineShortNames()
	stale[windowsPathKey(testProgramFilesX86)] = "PROGRA~3"
	for _, tc := range []struct {
		kernelPath string
		names      map[string]string
		err        error
	}{
		{testGUIShortKernelImage, nil, nil},
		{`\Device\HarddiskVolume3\Program Files (x86)\Cisco\CISCOS~1\UI\csc_ui.exe`, nil, nil},
		{testGUIShortKernelImage, stale, nil},
		{testGUIShortKernelImage, nil, errors.New("access denied")},
	} {
		peer := genuineWindowsPeer()
		peer.process.ImagePath = tc.kernelPath
		peer.shortNames, peer.shortNameErr = tc.names, tc.err
		_, reason := authenticateFake(t, peer)
		if !strings.Contains(reason, "not an allowed Secure Client GUI executable") ||
			!strings.Contains(reason, "8.3 short name") {
			t.Errorf("%q: reason = %q, want a refusal naming the 8.3 short path", tc.kernelPath, reason)
		}
		if opened := peer.opened(); len(opened) != 0 {
			t.Errorf("%q: gateway opened %q", tc.kernelPath, opened)
		}
	}
	peer := genuineWindowsPeer()
	peer.process.ImagePath = `\Device\HarddiskVolume3\Users\alice\Downloads\csc_ui.exe`
	if _, reason := authenticateFake(t, peer); strings.Contains(reason, "8.3") {
		t.Fatalf("reason for a path without '~' = %q", reason)
	}
}

// unicodeFoldVariants returns every copy of path with one ASCII letter
// replaced by a non-ASCII rune that Unicode simple folding (and so
// strings.EqualFold) treats as the same letter, such as U+017F for "s"
// and U+212A for "k". NTFS keeps each of these a different name.
func unicodeFoldVariants(t *testing.T, path string) []string {
	t.Helper()
	var variants []string
	for i, r := range path {
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < utf8.RuneSelf {
				continue
			}
			variant := path[:i] + string(f) + path[i+utf8.RuneLen(r):]
			if !strings.EqualFold(variant, path) {
				t.Fatalf("premise: EqualFold(%q, %q) = false", variant, path)
			}
			variants = append(variants, variant)
		}
	}
	return variants
}

// TestWindowsPeerAuthRejectsUnicodeFoldLookAlikes is the regression for
// the look-alike image path: a standard user can create a directory at
// the root of the system drive whose name differs from Program Files
// only by a character that Unicode folding equates with an ASCII
// letter. The gateway must refuse a process started from it without
// opening anything, because the file it would open and verify is the
// genuine GUI, not the one the peer runs.
func TestWindowsPeerAuthRejectsUnicodeFoldLookAlikes(t *testing.T) {
	kernelVariants := unicodeFoldVariants(t, testGUIKernelImage)
	longS := `\Device\HarddiskVolume3\Program File` + "\u017f" + ` (x86)\Cisco\Cisco Secure Client\UI\csc_ui.exe`
	kelvin := `\Device\Harddis` + "\u212a" + `Volume3\Program Files (x86)\Cisco\Cisco Secure Client\UI\csc_ui.exe`
	for _, want := range []string{longS, kelvin} {
		if !slices.Contains(kernelVariants, want) {
			t.Fatalf("fold variants miss %q", want)
		}
	}
	for _, kernelPath := range kernelVariants {
		peer := genuineWindowsPeer()
		peer.process.ImagePath = kernelPath
		_, reason := authenticateFake(t, peer)
		if !strings.Contains(reason, "not an allowed Secure Client GUI executable") {
			t.Errorf("%q: reason = %q", kernelPath, reason)
		}
		if opened := peer.opened(); len(opened) != 0 {
			t.Errorf("%q: gateway opened %q", kernelPath, opened)
		}
	}

	// The drive-letter side: the opened file's final path must match the
	// allowed path by the same rule before WinVerifyTrust runs.
	policy := testWindowsPeerPolicy(t)
	finalVariants := unicodeFoldVariants(t, testGUIImage)
	if len(finalVariants) == 0 {
		t.Fatal("no fold variants of the allowed drive path")
	}
	for _, finalPath := range finalVariants {
		if policy.allowsImage(finalPath) {
			t.Errorf("allowsImage(%q) = true", finalPath)
		}
		peer := genuineWindowsPeer()
		peer.image.finalPath = finalPath
		_, reason := authenticateFake(t, peer)
		if !strings.Contains(reason, "not an allowed Secure Client GUI executable") {
			t.Errorf("final path %q: reason = %q", finalPath, reason)
		}
		if peer.image.verified {
			t.Errorf("final path %q: WinVerifyTrust ran", finalPath)
		}
	}
}

func TestSameWindowsPathFoldsASCIIOnly(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{testGUIImage, testGUIImage, true},
		{testGUIImage, strings.ToUpper(testGUIImage), true},
		{testGUIKernelImage, strings.ToLower(testGUIKernelImage), true},
		{`C:\Files`, `C:\File` + "\u017f", false},
		{`C:\Files`, `C:\FILE` + "\u017f", false},
		{`C:\Kit`, `C:\` + "\u212a" + `it`, false},
		{`C:\Kit`, `C:\` + "\u212a" + `IT`, false},
		// Non-ASCII letters are compared exactly, even where NTFS would
		// treat the two cases as one name: refusing is the safe side.
		{`C:\` + "\u00c9", `C:\` + "\u00e9", false},
		{`C:\` + "\u00e9", `C:\` + "\u00e9", true},
		{`C:\a` + "\ufffd", `C:\a` + "\ufffd", false},
		{"C:\\a\xff", "C:\\a\xff", false},
		{`C:\a`, `C:\a\`, false},
		{`C:\a`, `C:\b`, false},
		{`C:\[`, `C:\{`, false},
		{`C:\@`, `C:\` + "`", false},
	} {
		if got := sameWindowsPath(tc.a, tc.b); got != tc.want {
			t.Errorf("sameWindowsPath(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
		if tc.want && windowsPathKey(tc.a) != windowsPathKey(tc.b) {
			t.Errorf("windowsPathKey(%q) != windowsPathKey(%q)", tc.a, tc.b)
		}
	}
	if windowsPathKey(`C:\Files`) == windowsPathKey(`C:\File`+"\u017f") {
		t.Fatal("windowsPathKey folded U+017F")
	}
}

// TestKernelImageNameRefusesLossyNames checks the UTF-16 conversion of
// the kernel image name: nothing that a lossy conversion would turn
// into a different, possibly allowed, name is accepted.
func TestKernelImageNameRefusesLossyNames(t *testing.T) {
	encode := func(s string) []uint16 { return utf16.Encode([]rune(s)) }
	name, err := kernelImageName(encode(testGUIKernelImage))
	if err != nil || name != testGUIKernelImage {
		t.Fatalf("kernelImageName = (%q, %v)", name, err)
	}
	pair := `\Device\HarddiskVolume3\` + "\U0001F600" + `\csc_ui.exe`
	if name, err := kernelImageName(encode(pair)); err != nil || name != pair {
		t.Fatalf("surrogate pair: (%q, %v)", name, err)
	}
	// A terminator counted in the length ends the name; it does not
	// change it.
	if name, err := kernelImageName(append(encode(testGUIKernelImage), 0, 0)); err != nil || name != testGUIKernelImage {
		t.Fatalf("counted terminator: (%q, %v)", name, err)
	}
	withNUL := append(encode(testGUIKernelImage), 0)
	withNUL = append(withNUL, encode(`\x.exe`)...)
	for label, units := range map[string][]uint16{
		"embedded NUL":       withNUL,
		"only NULs":          {0, 0},
		"empty":              {},
		"lone high":          append(encode(`\Device\a`), 0xd800),
		"lone high then NUL": append(encode(`\Device\a`), 0xd800, 0),
		"high then ASCII":    append(append(encode(`\Device\a`), 0xd83d), encode("b")...),
		"lone low":           append(encode(`\Device\a`), 0xdc00),
		"low then high":      append(encode(`\Device\a`), 0xde00, 0xd83d),
		"high then high":     append(encode(`\Device\a`), 0xd83d, 0xd83d, 0xde00),
		"leading NUL":        append([]uint16{0}, encode(testGUIKernelImage)...),
		"high at very start": append([]uint16{0xd800}, encode(`\x`)...),
	} {
		if name, err := kernelImageName(units); err == nil {
			t.Errorf("%s: accepted as %q", label, name)
		}
	}
}

// TestWindowsPeerAuthRejectsUnauthenticatedPeers covers the peers the
// Windows IPC used to accept: any process of any authenticated user.
func TestWindowsPeerAuthRejectsUnauthenticatedPeers(t *testing.T) {
	cases := []struct {
		name       string
		mutate     func(*fakeWindowsPeer)
		wantReason string
		wantVerify bool
	}{
		{
			name:       "peer pid unavailable",
			mutate:     func(p *fakeWindowsPeer) { p.pidErr = errors.New("ioctl failed") },
			wantReason: "peer pid unavailable",
		},
		{
			name:       "system pid",
			mutate:     func(p *fakeWindowsPeer) { p.pid = 4 },
			wantReason: "not a user process",
		},
		{
			name:       "process lookup failure",
			mutate:     func(p *fakeWindowsPeer) { p.processErr = errors.New("gone") },
			wantReason: "peer process lookup failed",
		},
		{
			name:       "missing creation time",
			mutate:     func(p *fakeWindowsPeer) { p.process.CreatedAt = time.Time{} },
			wantReason: "creation time unavailable",
		},
		{
			name:       "image cannot be opened",
			mutate:     func(p *fakeWindowsPeer) { p.imageErr = errors.New("sharing violation") },
			wantReason: "peer image unavailable",
		},
		{
			name: "arbitrary user tool",
			mutate: func(p *fakeWindowsPeer) {
				p.process.ImagePath = `\Device\HarddiskVolume3\Users\alice\Downloads\tool.exe`
			},
			wantReason: "not an allowed Secure Client GUI executable",
		},
		{
			name: "genuine GUI copied outside Program Files",
			mutate: func(p *fakeWindowsPeer) {
				p.process.ImagePath = `\Device\HarddiskVolume3\Users\alice\AppData\Local\Temp\UI\csc_ui.exe`
			},
			wantReason: "not an allowed Secure Client GUI executable",
		},
		{
			name: "other Cisco binary in the Secure Client tree",
			mutate: func(p *fakeWindowsPeer) {
				p.process.ImagePath = `\Device\HarddiskVolume3\Program Files (x86)\Cisco\Cisco Secure Client\vpnagent.exe`
			},
			wantReason: "not an allowed Secure Client GUI executable",
		},
		{
			name: "GUI name in a sibling directory",
			mutate: func(p *fakeWindowsPeer) {
				p.process.ImagePath = `\Device\HarddiskVolume3\Program Files (x86)\Cisco\Cisco Secure Client\DefenseClaw\UI\csc_ui.exe`
			},
			wantReason: "not an allowed Secure Client GUI executable",
		},
		{
			name: "GUI path under another volume",
			mutate: func(p *fakeWindowsPeer) {
				p.process.ImagePath = `\Device\HarddiskVolume4\Program Files (x86)\Cisco\Cisco Secure Client\UI\csc_ui.exe`
			},
			wantReason: "not an allowed Secure Client GUI executable",
		},
		{
			name: "opened file resolves outside the allowed path",
			mutate: func(p *fakeWindowsPeer) {
				p.image.finalPath = `C:\Users\alice\AppData\Local\Temp\UI\csc_ui.exe`
			},
			wantReason: "not an allowed Secure Client GUI executable",
		},
		{
			name: "opened file resolves to the other allowed root",
			mutate: func(p *fakeWindowsPeer) {
				p.image.finalPath = `C:\Program Files\Cisco\Cisco Secure Client\UI\csc_ui.exe`
			},
			wantReason: "not an allowed Secure Client GUI executable",
		},
		{
			name: "non-canonical final path",
			mutate: func(p *fakeWindowsPeer) {
				p.image.finalPath = `C:\Program Files (x86)\Cisco\Cisco Secure Client\UI\..\UI\csc_ui.exe`
			},
			wantReason: "not an allowed Secure Client GUI executable",
		},
		{
			name: "unsigned image at the GUI path",
			mutate: func(p *fakeWindowsPeer) {
				p.image.signerErr = errors.New("TRUST_E_NOSIGNATURE")
			},
			wantReason: "signature rejected",
			wantVerify: true,
		},
		{
			name: "trusted non-Cisco signer",
			mutate: func(p *fakeWindowsPeer) {
				p.image.signer = windowsImageSigner{CommonName: "Contoso Ltd", Organizations: []string{"Contoso Ltd"}}
			},
			wantReason: `signer "Contoso Ltd" is not allowed`,
			wantVerify: true,
		},
		{
			name: "Cisco common name with another organization",
			mutate: func(p *fakeWindowsPeer) {
				p.image.signer.Organizations = []string{"Contoso Ltd"}
			},
			wantReason: `organization "Contoso Ltd" is not allowed`,
			wantVerify: true,
		},
		{
			name: "signer without common name",
			mutate: func(p *fakeWindowsPeer) {
				p.image.signer = windowsImageSigner{Organizations: []string{testCiscoSigner}}
			},
			wantReason: "no subject common name",
			wantVerify: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			peer := genuineWindowsPeer()
			tc.mutate(peer)
			_, reason := authenticateFake(t, peer)
			if reason == "" {
				t.Fatal("peer admitted, want rejection")
			}
			if !strings.Contains(reason, tc.wantReason) {
				t.Fatalf("reason = %q, want substring %q", reason, tc.wantReason)
			}
			if peer.image.verified != tc.wantVerify {
				t.Fatalf("WinVerifyTrust ran = %v, want %v (path checks must run first)", peer.image.verified, tc.wantVerify)
			}
			if len(peer.opened()) > 0 && peer.imageErr == nil && !peer.image.closed {
				t.Fatal("opened image was not closed")
			}
		})
	}
}

// TestWindowsPeerAuthListenerClosesRejectedConnections drives Accept
// end to end: a rejected peer is closed before any byte is served and
// logged, and the next, genuine peer is returned.
func TestWindowsPeerAuthListenerClosesRejectedConnections(t *testing.T) {
	rejectedServer, rejectedClient := net.Pipe()
	acceptedServer, acceptedClient := net.Pipe()
	defer rejectedClient.Close()
	defer acceptedClient.Close()
	inner := newQueueListener(rejectedServer, acceptedServer)

	genuine := genuineWindowsPeer()
	resolvers := genuine.resolvers()
	resolvers.peerPID = func(c net.Conn) (uint32, error) {
		if c == rejectedServer {
			return 5150, nil
		}
		return genuine.pid, nil
	}
	resolvers.process = func(pid uint32) (windowsPeerProcess, error) {
		if pid == 5150 {
			return windowsPeerProcess{
				ImagePath: `\Device\HarddiskVolume3\Users\mallory\gui.exe`,
				SessionID: 2,
				CreatedAt: testProcessCreatedAt,
			}, nil
		}
		return genuine.process, nil
	}

	rejected := make(chan windowsPeerIdentity, 4)
	listener, err := newWindowsPeerAuthListener(inner, testWindowsPeerPolicy(t), resolvers,
		func(id windowsPeerIdentity, reason string) {
			if !strings.Contains(reason, "not an allowed Secure Client GUI executable") {
				t.Errorf("reject reason = %q", reason)
			}
			rejected <- id
		})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	got, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if got != acceptedServer {
		t.Fatal("Accept returned the rejected connection")
	}
	select {
	case id := <-rejected:
		if id.PID != 5150 || id.SessionID != 2 {
			t.Fatalf("rejected = %+v", id)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("rejection was not logged")
	}
	if opened := genuine.opened(); len(opened) != 1 || opened[0] != testGUIImage {
		t.Fatalf("opened = %q, want only the genuine GUI's policy path", opened)
	}
	_ = rejectedClient.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := rejectedClient.Read(make([]byte, 1)); err == nil {
		t.Fatal("rejected connection is still open")
	}
}

// blockingPeerResolvers returns resolvers under which every connection
// is a genuine GUI. For connections in slow, the process lookup blocks
// until release is closed; inFlight and maxInFlight count those
// blocked lookups.
func blockingPeerResolvers(slow map[net.Conn]bool, release <-chan struct{}, inFlight, maxInFlight *atomic.Int32) windowsPeerResolvers {
	const slowPID = 7000
	genuine := genuineWindowsPeer()
	resolvers := genuine.resolvers()
	resolvers.peerPID = func(c net.Conn) (uint32, error) {
		if slow[c] {
			return slowPID, nil
		}
		return genuine.pid, nil
	}
	resolvers.process = func(pid uint32) (windowsPeerProcess, error) {
		if pid == slowPID {
			n := inFlight.Add(1)
			for {
				seen := maxInFlight.Load()
				if n <= seen || maxInFlight.CompareAndSwap(seen, n) {
					break
				}
			}
			<-release
			inFlight.Add(-1)
		}
		return genuine.process, nil
	}
	return resolvers
}

// TestWindowsPeerAuthListenerSlowCheckDoesNotStallOthers keeps one
// peer's check blocked and verifies that a genuine GUI connecting
// after it is still admitted, that the blocked connection is closed at
// the deadline, and that Close returns while the check is in flight.
func TestWindowsPeerAuthListenerSlowCheckDoesNotStallOthers(t *testing.T) {
	slowServer, slowClient := net.Pipe()
	genuineServer, genuineClient := net.Pipe()
	defer slowClient.Close()
	defer genuineClient.Close()
	inner := newQueueListener(slowServer, genuineServer)

	release := make(chan struct{})
	defer close(release)
	var inFlight, maxInFlight atomic.Int32
	resolvers := blockingPeerResolvers(map[net.Conn]bool{slowServer: true}, release, &inFlight, &maxInFlight)

	rejected := make(chan string, 4)
	listener, err := newWindowsPeerAuthListenerWithLimits(inner, testWindowsPeerPolicy(t), resolvers,
		func(_ windowsPeerIdentity, reason string) { rejected <- reason },
		100*time.Millisecond, 4)
	if err != nil {
		t.Fatal(err)
	}

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := listener.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	select {
	case c := <-accepted:
		if c != genuineServer {
			t.Fatal("Accept returned the connection whose check is still running")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a blocked peer check stalled admission of the genuine GUI")
	}

	select {
	case reason := <-rejected:
		if !strings.Contains(reason, "did not finish within") {
			t.Fatalf("reason = %q, want a timeout", reason)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked peer check was not timed out")
	}
	_ = slowClient.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := slowClient.Read(make([]byte, 1)); err == nil {
		t.Fatal("timed-out connection is still open")
	}

	closed := make(chan error, 1)
	go func() { closed <- listener.Close() }()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("Close waited for an in-flight peer check")
	}
	acceptErr := make(chan error, 1)
	go func() {
		_, err := listener.Accept()
		acceptErr <- err
	}()
	select {
	case err := <-acceptErr:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept after Close = %v, want net.ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Accept after Close did not return")
	}
}

// TestWindowsPeerAuthListenerBoundsConcurrentChecks keeps every check
// blocked and verifies the number running at once never exceeds the
// cap, then releases them and admits the genuine peers.
func TestWindowsPeerAuthListenerBoundsConcurrentChecks(t *testing.T) {
	const maxPending = 2
	var servers []net.Conn
	slow := make(map[net.Conn]bool)
	for i := 0; i < 5; i++ {
		server, client := net.Pipe()
		defer client.Close()
		servers = append(servers, server)
		slow[server] = true
	}
	inner := newQueueListener(servers...)
	release := make(chan struct{})
	var inFlight, maxInFlight atomic.Int32
	resolvers := blockingPeerResolvers(slow, release, &inFlight, &maxInFlight)
	listener, err := newWindowsPeerAuthListenerWithLimits(inner, testWindowsPeerPolicy(t), resolvers,
		func(windowsPeerIdentity, string) {}, time.Minute, maxPending)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	admitted := make(chan net.Conn, len(servers))
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			admitted <- c
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for inFlight.Load() < maxPending && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond)
	if got := inFlight.Load(); got != maxPending {
		t.Fatalf("in-flight checks = %d, want %d", got, maxPending)
	}
	close(release)
	for i := range servers {
		select {
		case <-admitted:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of %d peers admitted after release", i, len(servers))
		}
	}
	if got := maxInFlight.Load(); got > maxPending {
		t.Fatalf("max in-flight checks = %d, cap %d", got, maxPending)
	}
}

// TestWindowsPeerAuthListenerPassesInnerErrors checks that a transient
// inner Accept error reaches the caller without stopping the loop, and
// a permanent one ends it.
func TestWindowsPeerAuthListenerPassesInnerErrors(t *testing.T) {
	genuineServer, genuineClient := net.Pipe()
	defer genuineClient.Close()
	transient := &scriptedListener{steps: []scriptedAccept{
		{err: temporaryError{}},
		{conn: genuineServer},
	}, closed: make(chan struct{})}
	listener, err := newWindowsPeerAuthListener(transient, testWindowsPeerPolicy(t), genuineWindowsPeer().resolvers(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if _, err := listener.Accept(); !errors.As(err, new(temporaryError)) {
		t.Fatalf("first Accept = %v, want the transient error", err)
	}
	if c, err := listener.Accept(); err != nil || c != genuineServer {
		t.Fatalf("second Accept = %v, %v, want the genuine conn", c, err)
	}

	permanentErr := errors.New("listener broke")
	permanent := &scriptedListener{steps: []scriptedAccept{{err: permanentErr}}, closed: make(chan struct{})}
	broken, err := newWindowsPeerAuthListener(permanent, testWindowsPeerPolicy(t), genuineWindowsPeer().resolvers(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer broken.Close()
	for i := 0; i < 2; i++ {
		if _, err := broken.Accept(); !errors.Is(err, permanentErr) {
			t.Fatalf("Accept after permanent failure = %v, want %v", err, permanentErr)
		}
	}
}

type temporaryError struct{}

func (temporaryError) Error() string   { return "temporary accept failure" }
func (temporaryError) Temporary() bool { return true }

type scriptedAccept struct {
	conn net.Conn
	err  error
}

// scriptedListener plays its steps in order, then blocks until closed.
type scriptedListener struct {
	mu     sync.Mutex
	steps  []scriptedAccept
	closed chan struct{}
	once   sync.Once
}

func (s *scriptedListener) Accept() (net.Conn, error) {
	s.mu.Lock()
	if len(s.steps) > 0 {
		step := s.steps[0]
		s.steps = s.steps[1:]
		s.mu.Unlock()
		return step.conn, step.err
	}
	s.mu.Unlock()
	<-s.closed
	return nil, net.ErrClosed
}

func (s *scriptedListener) Close() error {
	s.once.Do(func() { close(s.closed) })
	return nil
}
func (s *scriptedListener) Addr() net.Addr { return &net.UnixAddr{Name: "scripted", Net: "unix"} }

// queueListener hands out the queued connections, then blocks until
// closed, like a listening socket with nothing pending.
type queueListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newQueueListener(conns ...net.Conn) *queueListener {
	q := &queueListener{conns: make(chan net.Conn, len(conns)), closed: make(chan struct{})}
	for _, c := range conns {
		q.conns <- c
	}
	return q
}

func (q *queueListener) Accept() (net.Conn, error) {
	select {
	case c := <-q.conns:
		return c, nil
	case <-q.closed:
		return nil, net.ErrClosed
	}
}

func (q *queueListener) Close() error {
	q.once.Do(func() { close(q.closed) })
	return nil
}
func (q *queueListener) Addr() net.Addr { return &net.UnixAddr{Name: "queue", Net: "unix"} }

func TestNewWindowsPeerPolicyFailsClosed(t *testing.T) {
	roots := []string{testProgramFilesX86}
	images := []string{`UI\csc_ui.exe`}
	signers := []string{testCiscoSigner}
	cases := map[string]struct {
		roots, images, signers []string
	}{
		"no roots":              {nil, images, signers},
		"no images":             {roots, nil, signers},
		"no signers":            {roots, images, nil},
		"relative root":         {[]string{`Program Files (x86)`}, images, signers},
		"unc root":              {[]string{`\\server\share`}, images, signers},
		"traversing image":      {roots, []string{`..\..\Users\Public\gui.exe`}, signers},
		"absolute image":        {roots, []string{`C:\Users\Public\gui.exe`}, signers},
		"forward-slash image":   {roots, []string{`UI/csc_ui.exe`}, signers},
		"padded signer":         {roots, images, []string{" Cisco Systems, Inc."}},
		"empty signer in list":  {roots, images, []string{testCiscoSigner, ""}},
		"empty image in list":   {roots, []string{`UI\csc_ui.exe`, ""}, signers},
		"stream-suffixed image": {roots, []string{`UI\csc_ui.exe:evil`}, signers},
	}
	for name, tc := range cases {
		if _, err := newWindowsPeerPolicy(tc.roots, tc.images, tc.signers, testDriveDevice); err == nil {
			t.Errorf("%s: newWindowsPeerPolicy accepted an unsafe policy", name)
		}
	}
	if _, err := newWindowsPeerPolicy(roots, images, signers, nil); err == nil {
		t.Error("newWindowsPeerPolicy accepted a nil drive device resolver")
	}
	for _, device := range []string{
		"",
		`\??\C:\substituted`,
		`\Device\LanmanRedirector\;Z:0000000000012345\server\share`,
		`\Device\Mup`,
		`\Device\WebDavRedirector`,
		`\Device\HarddiskVolume3\`,
		`C:`,
		"\\Device\\Harddisk\x00Volume3",
	} {
		resolve := func(string) (string, error) { return device, nil }
		if _, err := newWindowsPeerPolicy(roots, images, signers, resolve); err == nil {
			t.Errorf("newWindowsPeerPolicy accepted drive device %q", device)
		}
	}
	failing := func(string) (string, error) { return "", errors.New("no mapping") }
	if _, err := newWindowsPeerPolicy(roots, images, signers, failing); err == nil {
		t.Error("newWindowsPeerPolicy accepted an unresolvable drive")
	}
	if _, err := newWindowsPeerAuthListener(stubListener{}, windowsPeerPolicy{}, genuineWindowsPeer().resolvers(), nil); err == nil {
		t.Error("listener accepted an empty policy")
	}
	incomplete := genuineWindowsPeer().resolvers()
	incomplete.openImage = nil
	if _, err := newWindowsPeerAuthListener(stubListener{}, testWindowsPeerPolicy(t), incomplete, nil); err == nil {
		t.Error("listener accepted an incomplete resolver set")
	}
	for _, limits := range []struct {
		timeout    time.Duration
		maxPending int
	}{{0, 1}, {time.Second, 0}} {
		if _, err := newWindowsPeerAuthListenerWithLimits(stubListener{}, testWindowsPeerPolicy(t),
			genuineWindowsPeer().resolvers(), nil, limits.timeout, limits.maxPending); err == nil {
			t.Errorf("listener accepted limits %+v", limits)
		}
	}
}

func TestNewWindowsPeerPolicyJoinsRootsAndImages(t *testing.T) {
	var resolvedDrives []string
	policy, err := newWindowsPeerPolicy(
		[]string{testProgramFilesX86, testProgramFiles, `C:\Program Files (x86)\`, `d:\Apps`},
		[]string{`UI\csc_ui.exe`, `UI\CSC_UI.EXE`},
		[]string{testCiscoSigner},
		func(drive string) (string, error) {
			resolvedDrives = append(resolvedDrives, drive)
			return testDriveDevice(drive)
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []windowsPeerAllowedImage{
		{testGUIImage, testGUIKernelImage, `\Device\HarddiskVolume3`},
		{
			`C:\Program Files\Cisco\Cisco Secure Client\UI\csc_ui.exe`,
			`\Device\HarddiskVolume3\Program Files\Cisco\Cisco Secure Client\UI\csc_ui.exe`,
			`\Device\HarddiskVolume3`,
		},
		{
			`d:\Apps\Cisco\Cisco Secure Client\UI\csc_ui.exe`,
			`\Device\HarddiskVolume4\Apps\Cisco\Cisco Secure Client\UI\csc_ui.exe`,
			`\Device\HarddiskVolume4`,
		},
	}
	if len(policy.images) != len(want) {
		t.Fatalf("images = %+v, want %+v", policy.images, want)
	}
	for i := range want {
		if policy.images[i] != want[i] {
			t.Fatalf("images[%d] = %+v, want %+v", i, policy.images[i], want[i])
		}
	}
	if strings.Join(resolvedDrives, ",") != "C:,D:" {
		t.Fatalf("resolved drives = %q, want each drive once", resolvedDrives)
	}
}

func TestIsCanonicalWindowsDrivePath(t *testing.T) {
	for _, path := range []string{`C:\`, `C:\Program Files (x86)\Cisco\UI\csc_ui.exe`, `z:\a b\c.exe`} {
		if !isCanonicalWindowsDrivePath(path) {
			t.Errorf("isCanonicalWindowsDrivePath(%q) = false", path)
		}
	}
	for _, path := range []string{
		``, `C:`, `C:relative`, `\\?\C:\x.exe`, `\\server\share\x.exe`, `\Device\HarddiskVolume3\x.exe`,
		`C:/Program Files/x.exe`, `C:\a\..\x.exe`, `C:\a\.\x.exe`, `C:\a\\x.exe`, `C:\x.exe:ads`,
		`C:\x.exe.`, `C:\dir \x.exe`, `1:\x.exe`, "C:\\x\x00.exe",
	} {
		if isCanonicalWindowsDrivePath(path) {
			t.Errorf("isCanonicalWindowsDrivePath(%q) = true", path)
		}
	}
}

func TestCodesignStateLabelReportsWindowsEnforcement(t *testing.T) {
	for _, requireFlags := range []bool{true, false} {
		if got := codesignStateLabel("windows", requireFlags, requireFlags, 0); got != codesignStateEnabled {
			t.Fatalf("windows label = %q, want %q", got, codesignStateEnabled)
		}
	}
}

func TestPeerAuthPolicyLogFieldsKeepsUnixFormatAndReportsWindowsPolicy(t *testing.T) {
	s := &Server{
		allowedTeamIDs:         []string{"T"},
		allowedSigningIDs:      []string{"S"},
		allowedBundleIDs:       []string{"B"},
		requireUnixPeer:        true,
		requireSigningMetadata: true,
		allowedWindowsSigners:  []string{testCiscoSigner},
		allowedWindowsImages:   []string{`UI\csc_ui.exe`},
	}
	want := "team_ids=[T] signing_ids=[S] bundle_ids=[B] require_unix_peer=true require_signing_metadata=true"
	if got := s.peerAuthPolicyLogFields("darwin"); got != want {
		t.Fatalf("darwin fields = %q, want %q", got, want)
	}
	got := s.peerAuthPolicyLogFields("windows")
	for _, fragment := range []string{
		`windows_signers=["Cisco Systems, Inc."]`,
		`windows_images=["UI\\csc_ui.exe"]`,
		"require_unix_peer=true",
		"require_signing_metadata=true",
	} {
		if !strings.Contains(got, fragment) {
			t.Fatalf("windows fields = %q, missing %q", got, fragment)
		}
	}
}

func TestNewServerSeedsWindowsPeerPolicy(t *testing.T) {
	// NewServer only keeps the store for later RPCs; a zero value
	// avoids the platform-specific storage ACL checks.
	store := &audit.Store{}
	newServer := func(managedIPC config.ManagedIPCConfig, mode string) *Server {
		t.Helper()
		managedIPC.SocketPath = filepath.Join(t.TempDir(), "ipc", SocketFileName)
		srv, err := NewServer(ServerOptions{
			Config: &config.Config{DataDir: t.TempDir(), DeploymentMode: mode, Managed: managedIPC},
			Health: gateway.NewSidecarHealth(),
			Store:  store,
			Logf:   func(string, ...any) {},
		})
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		return srv
	}
	for _, mode := range []string{"managed_enterprise", ""} {
		srv := newServer(config.ManagedIPCConfig{}, mode)
		if len(srv.allowedWindowsSigners) != 1 || srv.allowedWindowsSigners[0] != config.SecureClientWindowsSigner {
			t.Fatalf("mode %q: signers = %q", mode, srv.allowedWindowsSigners)
		}
		if len(srv.allowedWindowsImages) != 1 || srv.allowedWindowsImages[0] != config.SecureClientWindowsGUIImage {
			t.Fatalf("mode %q: images = %q", mode, srv.allowedWindowsImages)
		}
	}
	srv := newServer(config.ManagedIPCConfig{
		AllowedWindowsSigners: []string{"Cisco Systems, Inc."},
		AllowedWindowsImages:  []string{`UI\csc_ui_next.exe`},
	}, "managed_enterprise")
	if len(srv.allowedWindowsImages) != 1 || srv.allowedWindowsImages[0] != `UI\csc_ui_next.exe` {
		t.Fatalf("override images = %q", srv.allowedWindowsImages)
	}
}
