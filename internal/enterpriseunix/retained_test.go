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
