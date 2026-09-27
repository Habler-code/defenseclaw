//go:build !windows

package enterpriseunix

import (
	"os"
	"testing"
)

// A non-purge uninstall keeps state; reinstalling (e.g. an MDM uninstall then
// install, or a pkg reinstall that cannot pass --adopt-existing) must succeed
// without adoption, while a replaced state directory is still refused.
func TestReinstallAfterNonPurgeUninstallRecognizesRetainedState(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			h := newTestHost(t, goos)
			l := h.env.Layout
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			// Gateway state accumulates while installed.
			if err := os.MkdirAll(h.env.P(l.DataDir), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(h.env.P(l.DataDir)+"/audit.db", []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			requireOK(t, h.run(Options{Action: ActionUninstall}))
			if !exists(h.env.retainedStatePath()) {
				t.Fatal("non-purge uninstall did not record its retained state")
			}
			again := h.run(Options{Action: ActionUninstall})
			requireOK(t, again)
			if hasWarning(again, codeLeftovers) {
				t.Fatal("retained state reported as unmanaged leftovers on a second uninstall")
			}
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			if exists(h.env.retainedStatePath()) {
				t.Fatal("retained-state record survived the reinstall")
			}
			if _, err := os.Stat(h.env.P(l.DataDir) + "/audit.db"); err != nil {
				t.Fatalf("reinstall lost retained gateway state: %v", err)
			}

			// A state directory replaced after the uninstall is not ours.
			requireOK(t, h.run(Options{Action: ActionUninstall}))
			if err := os.RemoveAll(h.env.P(l.DataDir)); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(h.env.P(l.DataDir), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(h.env.P(l.DataDir)+"/planted", []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			requireError(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}), codeUnmanagedLayout)
		})
	}
}

// ext4 and XFS reuse a freed inode number for the next directory created,
// so a state directory deleted and recreated in place can carry the device,
// inode and owner uninstall recorded. The marker uninstall leaves inside
// the directory still tells the two apart.
func TestRetainedStateNeedsTheUninstallMarker(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			for name, tamper := range map[string]func(h *testHost, marker string){
				// Same directory identity, no marker: what a recreated directory
				// on a reused inode looks like.
				"marker missing": func(h *testHost, marker string) {
					if err := os.Remove(marker); err != nil {
						t.Fatal(err)
					}
				},
				"marker forged": func(h *testHost, marker string) {
					if err := h.env.writeFileAtomic(marker, []byte("0000\n"), 0o600, rootOwner()); err != nil {
						t.Fatal(err)
					}
				},
				"marker not root-owned": func(h *testHost, marker string) {
					h.owners[marker] = [2]int{1000, 1000}
				},
			} {
				t.Run(name, func(t *testing.T) {
					h := newTestHost(t, goos)
					l := h.env.Layout
					requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
					if err := os.WriteFile(h.env.P(l.DataDir)+"/audit.db", []byte("x"), 0o600); err != nil {
						t.Fatal(err)
					}
					requireOK(t, h.run(Options{Action: ActionUninstall}))
					marker := retainedMarkerPath(h.env.P(l.DataDir))
					if !exists(marker) {
						t.Fatal("non-purge uninstall left no marker in the kept state directory")
					}
					tamper(h, marker)
					requireError(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}), codeUnmanagedLayout)
				})
			}
		})
	}
}

// A reinstall that resumes the kept state removes the markers, so the
// running deployment's directories hold only its own files.
func TestReinstallRemovesTheRetainedMarkers(t *testing.T) {
	h := newTestHost(t, "linux")
	l := h.env.Layout
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	if err := os.WriteFile(h.env.P(l.DataDir)+"/audit.db", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	requireOK(t, h.run(Options{Action: ActionUninstall}))
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	if exists(retainedMarkerPath(h.env.P(l.DataDir))) {
		t.Fatal("the retained marker survived the reinstall")
	}
}
