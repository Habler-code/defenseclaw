// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

func codexPinModel(t *testing.T, raw []byte) map[string]interface{} {
	t.Helper()
	model := map[string]interface{}{}
	if err := toml.Unmarshal(raw, &model); err != nil {
		t.Fatalf("rendered requirements do not parse: %v\n%s", err, raw)
	}
	return model
}

func requireCodexPinRoundTrip(t *testing.T, original []byte) []byte {
	t.Helper()
	rendered, changed, err := renderCodexRequirementsPin(original)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !changed {
		t.Fatal("render reported no change for a document without the pin")
	}
	features, _ := codexPinModel(t, rendered)["features"].(map[string]interface{})
	if features["hooks"] != true {
		t.Fatalf("rendered requirements do not pin features.hooks:\n%s", rendered)
	}
	if state, err := inspectCodexRequirementsPin(rendered); err != nil || state != CodexRequirementsPinOwned {
		t.Fatalf("rendered state = %q, %v; want owned", state, err)
	}
	again, changed, err := renderCodexRequirementsPin(rendered)
	if err != nil || changed || !bytes.Equal(again, rendered) {
		t.Fatalf("second render changed=%t err=%v", changed, err)
	}
	restored, removeFile, changed, err := removeCodexRequirementsPin(rendered)
	if err != nil || !changed {
		t.Fatalf("remove: changed=%t err=%v", changed, err)
	}
	if len(bytes.TrimSpace(original)) == 0 {
		if !removeFile {
			t.Fatalf("created file was not marked for removal: %q", restored)
		}
		return rendered
	}
	if removeFile {
		t.Fatal("administrator content was marked for file removal")
	}
	// The pin needs the last administrator line terminated; that line ending
	// is the only byte removal leaves behind.
	want := original
	if !bytes.HasSuffix(original, []byte("\n")) {
		want = append(append([]byte(nil), original...), '\n')
	}
	if !bytes.Equal(restored, want) {
		t.Fatalf("removal did not restore the original bytes:\n--- got\n%q\n--- want\n%q", restored, want)
	}
	return rendered
}

func TestCodexRequirementsPinCreatesAndRemovesOwnedFile(t *testing.T) {
	rendered := requireCodexPinRoundTrip(t, nil)
	want := codexRequirementsPinRegionBegin + "\n[features]\nhooks = true\n" + codexRequirementsPinRegionEnd + "\n"
	if string(rendered) != want {
		t.Fatalf("created requirements = %q, want %q", rendered, want)
	}
	if strings.Contains(string(rendered), "allow_managed_hooks_only") {
		t.Fatal("the macOS pin must not lock Codex to managed hooks")
	}
}

func TestCodexRequirementsPinPreservesAdministratorContent(t *testing.T) {
	const (
		region = "region"
		line   = "line"
		dotted = "dotted"
	)
	cases := map[string]struct {
		original string
		form     string
	}{
		"no features table": {
			"# Fleet policy\nallowed_approval_policies = [\"on-request\"]\n\n[hooks]\nmanaged_dir = \"/opt/acme\" # vendor hooks\n",
			region,
		},
		"features header": {
			"model = \"o5\"\n\n[features] # fleet flags\nweb_search = true\n\n[mcp_servers.acme]\ncommand = \"acme\"\n",
			line,
		},
		"features header on unterminated last line": {"model = \"o5\"\n[features]", line},
		"dotted root features": {
			"features.web_search = true\nmodel = \"o5\"\n[hooks]\nmanaged_dir = \"/opt/acme\"\n",
			dotted,
		},
		"implicit features table":     {"[features.experimental]\nfoo = 1\n", region},
		"no trailing newline":         {"model = \"o5\"", region},
		"crlf":                        {"model = \"o5\"\r\n[sandbox]\r\nmode = \"read-only\"\r\n", region},
		"header text inside a string": {"note = \"\"\"\n[features]\nhooks = false\n\"\"\"\n", region},
		"whitespace only":             {"\n\n", region},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			rendered := requireCodexPinRoundTrip(t, []byte(tc.original))
			switch tc.form {
			case region:
				if !bytes.HasPrefix(rendered, []byte(tc.original)) ||
					!bytes.Contains(rendered, []byte(codexRequirementsPinRegionBegin)) {
					t.Fatalf("pin was not appended after the administrator bytes:\n%s", rendered)
				}
			case line:
				if !bytes.Contains(rendered, []byte("hooks = true "+codexRequirementsPinLineMarker)) ||
					bytes.Contains(rendered, []byte(codexRequirementsPinRegionBegin)) {
					t.Fatalf("pin was not added to the administrator [features] table:\n%s", rendered)
				}
			case dotted:
				if !bytes.HasPrefix(rendered, []byte("features.hooks = true "+codexRequirementsPinLineMarker)) {
					t.Fatalf("dotted pin was not added as a root key:\n%s", rendered)
				}
			}
			if strings.Contains(tc.original, "\r\n") && !strings.Contains(string(rendered), codexRequirementsPinRegionEnd+"\r\n") {
				t.Fatalf("CRLF document received LF-only pin lines: %q", rendered)
			}
		})
	}
}

func TestCodexRequirementsPinLeavesAdministratorPinAlone(t *testing.T) {
	for _, original := range []string{
		"[features]\nhooks = true\n",
		"features = { hooks = true }\n",
		"features.hooks = true\n",
	} {
		rendered, changed, err := renderCodexRequirementsPin([]byte(original))
		if err != nil || changed || string(rendered) != original {
			t.Fatalf("administrator pin %q: changed=%t err=%v", original, changed, err)
		}
		if state, err := inspectCodexRequirementsPin([]byte(original)); err != nil || state != CodexRequirementsPinAdministrator {
			t.Fatalf("administrator pin %q state = %q, %v", original, state, err)
		}
		restored, removeFile, changed, err := removeCodexRequirementsPin([]byte(original))
		if err != nil || changed || removeFile || string(restored) != original {
			t.Fatalf("removal touched an administrator pin %q: changed=%t removeFile=%t err=%v", original, changed, removeFile, err)
		}
	}
}

func TestCodexRequirementsPinRefusesConflictsAndUneditableLayouts(t *testing.T) {
	for name, original := range map[string]string{
		"administrator disables hooks": "[features]\nhooks = false\n",
		"non-boolean hooks":            "[features]\nhooks = \"on\"\n",
		"inline features table":        "features = { web_search = true }\n",
		"features array of tables":     "[[features]]\nname = \"x\"\n",
		"features scalar":              "features = 1\n",
		"invalid toml":                 "[features\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, changed, err := renderCodexRequirementsPin([]byte(original)); err == nil || changed {
				t.Fatalf("render accepted %q: changed=%t err=%v", original, changed, err)
			}
		})
	}
	_, err := inspectCodexRequirementsPin([]byte("[features]\nhooks = false\n"))
	if err == nil || !strings.Contains(err.Error(), "hooks = false") {
		t.Fatalf("inspect of a disabling requirement = %v", err)
	}
	if _, _, err := renderCodexRequirementsPin([]byte("features = { web_search = true }\n")); !errors.Is(err, errCodexRequirementsPinUneditable) {
		t.Fatalf("inline table error = %v, want the manual-edit guidance", err)
	}
}

// A change inside DefenseClaw's region is administrator content; removal must
// fail closed instead of deleting it.
func TestCodexRequirementsPinRemovalFailsClosedOnEditedRegion(t *testing.T) {
	rendered, _, err := renderCodexRequirementsPin([]byte("model = \"o5\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	edited := bytes.Replace(rendered, []byte("hooks = true\n"), []byte("hooks = true\nweb_search = true\n"), 1)
	if _, _, changed, err := removeCodexRequirementsPin(edited); err == nil || changed {
		t.Fatalf("removal of an edited region: changed=%t err=%v", changed, err)
	}
	// A document without DefenseClaw bytes is left unchanged.
	restored, removeFile, changed, err := removeCodexRequirementsPin([]byte("model = \"o5\"\n"))
	if err != nil || changed || removeFile || string(restored) != "model = \"o5\"\n" {
		t.Fatalf("removal from a clean document: changed=%t removeFile=%t err=%v", changed, removeFile, err)
	}
}

// With the dotted root layout, the administrator may later delete their own
// features.* keys. Removing DefenseClaw's line then leaves no features table,
// which is what the administrator's document means.
func TestCodexRequirementsPinRemovesDottedPinAfterAdministratorFeaturesAreGone(t *testing.T) {
	rendered, _, err := renderCodexRequirementsPin([]byte("features.web = true\n[otel]\nx = 1\n"))
	if err != nil {
		t.Fatal(err)
	}
	edited := bytes.Replace(rendered, []byte("features.web = true\n"), nil, 1)
	restored, removeFile, changed, err := removeCodexRequirementsPin(edited)
	if err != nil || !changed || removeFile || string(restored) != "[otel]\nx = 1\n" {
		t.Fatalf("remove = %q, removeFile=%t changed=%t err=%v", restored, removeFile, changed, err)
	}
}

// DefenseClaw bytes that cannot be removed exactly are reported, so the
// uninstaller warns instead of leaving the pin in place silently.
func TestCodexRequirementsPinRemovalReportsUnremovableOwnedBytes(t *testing.T) {
	rendered, _, err := renderCodexRequirementsPin([]byte("model = \"o5\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	end := []byte(codexRequirementsPinRegionEnd + "\n")
	for name, edited := range map[string][]byte{
		"missing END marker":        bytes.Replace(rendered, end, nil, 1),
		"stray BEGIN marker":        append([]byte(codexRequirementsPinRegionBegin+"\n"), rendered...),
		"missing BEGIN marker":      bytes.Replace(rendered, []byte(codexRequirementsPinRegionBegin+"\n"), nil, 1),
		"stray leading END":         append(append([]byte(nil), end...), rendered...),
		"stray trailing END":        append(append([]byte(nil), rendered...), end...),
		"edited region":             bytes.Replace(rendered, []byte("hooks = true\n"), []byte("hooks = true\nweb_search = true\n"), 1),
		"CRLF missing BEGIN marker": bytes.ReplaceAll(bytes.Replace(rendered, []byte(codexRequirementsPinRegionBegin+"\n"), nil, 1), []byte("\n"), []byte("\r\n")),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, changed, err := removeCodexRequirementsPin(edited)
			if changed || !errors.Is(err, errCodexRequirementsPinUnremovable) {
				t.Fatalf("remove: changed=%t err=%v, want the manual-removal guidance", changed, err)
			}
			if !strings.Contains(err.Error(), "delete the lines marked") {
				t.Fatalf("removal guidance = %q", err)
			}
			// The pin is still in force and DefenseClaw marked it, so it is
			// not reported as the administrator's own pin.
			if state, err := inspectCodexRequirementsPin(edited); err != nil || state != CodexRequirementsPinOwned {
				t.Fatalf("inspect = %q, %v; want owned", state, err)
			}
		})
	}
}
