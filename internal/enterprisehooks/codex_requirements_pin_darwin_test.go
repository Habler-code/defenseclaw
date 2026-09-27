// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package enterprisehooks

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// A write-capable macOS ACL leaves the mode bits unchanged. The pin must
// refuse it on the requirements directory and file, as the Codex connector
// does when it reads the pin.
func TestCodexRequirementsPinRefusesWriteCapableDarwinACL(t *testing.T) {
	for target, entry := range map[string]string{
		"directory": "everyone allow add_file,delete_child,file_inherit",
		"file":      "everyone allow write,append",
	} {
		t.Run(target, func(t *testing.T) {
			dir, path := codexPinTestLayout(t)
			if err := os.Mkdir(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			original := []byte("[features]\nweb_search = true\n")
			if err := os.WriteFile(path, original, 0o644); err != nil {
				t.Fatal(err)
			}
			refused := map[string]string{"directory": dir, "file": path}[target]
			if output, err := exec.Command("/bin/chmod", "+a", entry, refused).CombinedOutput(); err != nil {
				t.Fatalf("add macOS ACL: %v: %s", err, output)
			}
			t.Cleanup(func() { _ = exec.Command("/bin/chmod", "-N", refused).Run() })
			if _, err := EnsureCodexRequirementsHooksPin(); err == nil || !strings.Contains(err.Error(), "ACL") {
				t.Fatalf("ensure with a write-capable %s ACL = %v", target, err)
			}
			if _, err := InspectCodexRequirementsHooksPin(); err == nil || !strings.Contains(err.Error(), "ACL") {
				t.Fatalf("inspect with a write-capable %s ACL = %v", target, err)
			}
			if data, _ := os.ReadFile(path); !bytes.Equal(data, original) {
				t.Fatalf("requirements changed: %q", data)
			}
		})
	}
}
