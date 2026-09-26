// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/pelletier/go-toml/v2"
)

func TestCodexRequirementsPinHooksParsesOnlyAnExplicitTrue(t *testing.T) {
	for raw, want := range map[string]bool{
		"[features]\nhooks = true\n":        true,
		"features.hooks = true\n":           true,
		"[features]\nhooks = false\n":       false,
		"[features]\nhooks = \"x\"\n":       false,
		"allow_managed_hooks_only = true\n": false,
		"":                                  false,
		"[features\n":                       false,
	} {
		if got := codexRequirementsPinHooks([]byte(raw)); got != want {
			t.Errorf("codexRequirementsPinHooks(%q) = %t, want %t", raw, got, want)
		}
	}
}

// An untrusted requirements source never counts as a pin.
func TestCodexUserHooksFeaturePinnedRequiresTrustedManagedSource(t *testing.T) {
	original := codexSystemRequirementsPathForInspection
	t.Cleanup(func() { codexSystemRequirementsPathForInspection = original })
	path := filepath.Join(t.TempDir(), "requirements.toml")
	if err := os.WriteFile(path, []byte("[features]\nhooks = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	codexSystemRequirementsPathForInspection = func() (string, error) { return path, nil }
	if codexUserHooksFeaturePinned(SetupOpts{ManagedEnterprise: true}) {
		t.Fatal("a user-writable requirements file was trusted as a hooks pin")
	}
	if codexUserHooksFeaturePinned(SetupOpts{}) {
		t.Fatal("an unmanaged setup consulted the machine hooks pin")
	}
}

// With machine requirements pinning [features] hooks = true, a user-level
// [features] hooks = false no longer turns Codex hooks off. A managed setup
// must then repair DefenseClaw's hooks instead of refusing, and the guardian
// must count them as present, so removing the hooks together with the flag is
// repaired. Without the pin the established refusal is unchanged.
func TestCodexManagedSetupRepairsHooksUnderMachineHooksPin(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("native Windows publishes the pin with its managed hook matrix")
	}
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.toml")
	userConfig := "model_provider = \"openai\"\n[features]\nhooks = false\n"
	if err := os.WriteFile(configPath, []byte(userConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	CodexConfigPathOverride = configPath
	originalInspector := codexPolicyInspector
	originalPinned := codexUserHooksFeaturePinned
	t.Cleanup(func() {
		CodexConfigPathOverride = ""
		codexPolicyInspector = originalInspector
		codexUserHooksFeaturePinned = originalPinned
	})
	codexPolicyInspector = func(context.Context, SetupOpts) (codexEffectivePolicy, error) {
		return codexEffectivePolicy{}, nil
	}
	pinned := false
	codexUserHooksFeaturePinned = func(SetupOpts) bool { return pinned }

	c := NewCodexConnector()
	opts := SetupOpts{
		DataDir:           dir,
		ProxyAddr:         "127.0.0.1:4000",
		APIAddr:           "127.0.0.1:18970",
		ManagedEnterprise: true,
	}
	if err := c.Setup(context.Background(), opts); err == nil || !strings.Contains(err.Error(), "hooks are disabled") {
		t.Fatalf("unpinned managed Setup error = %v, want the disabled-hooks refusal", err)
	}

	pinned = true
	if err := c.Setup(context.Background(), opts); err != nil {
		t.Fatalf("pinned managed Setup: %v", err)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg := map[string]interface{}{}
	if err := toml.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if hooks, _ := cfg["hooks"].(map[string]interface{}); len(hooks) == 0 {
		t.Fatalf("pinned Setup did not write DefenseClaw hooks:\n%s", raw)
	}
	if features, _ := cfg["features"].(map[string]interface{}); features["hooks"] != false {
		t.Fatalf("pinned Setup rewrote the user's inactive flag: %#v", cfg["features"])
	}
	present, err := c.ownedHookContractPresent(opts)
	if err != nil || !present {
		t.Fatalf("guardian presence under the pin = %t, %v; want present", present, err)
	}
	pinned = false
	if present, err := c.ownedHookContractPresent(opts); err != nil || present {
		t.Fatalf("guardian presence without the pin = %t, %v; want absent", present, err)
	}
}
