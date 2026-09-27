// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// TestSecureClientGoldenDotEnvProfilePin pins that a .env file in the data
// directory cannot supply the enterprise profile pin. Secure Client services
// never carry the pin, so a writable .env line would otherwise become it and
// move a Secure Client gateway onto the standalone decision stack. The
// resolution is computed for both Secure Client platforms, so the golden is
// platform independent. See testdata/secure_client_golden/README.md.
func TestSecureClientGoldenDotEnvProfilePin(t *testing.T) {
	unsetEnvironmentForDotenvTest(t, managed.EnterpriseProfileEnv, managed.DeploymentModeEnv)
	path := filepath.Join(t.TempDir(), ".env")
	body := []byte(managed.EnterpriseProfileEnv + "=" + managed.ProfileStandalone + "\n")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("write dotenv: %v", err)
	}

	loadDotEnvIntoOS(path)

	pin, pinLoaded := os.LookupEnv(managed.EnterpriseProfileEnv)
	result := map[string]any{
		"dotenv_profile_pin_loaded": pinLoaded,
	}
	resolved := map[string]string{}
	for _, goos := range []string{"darwin", "windows"} {
		// The Secure Client shape: managed_enterprise, no enterprise block.
		profile, err := managed.ResolveEnterpriseProfile(goos, managed.DeploymentModeManagedEnterprise, pin, "")
		if err != nil {
			resolved[goos] = "error: " + err.Error()
			continue
		}
		resolved[goos] = profile
	}
	result["secure_client_shape_resolves"] = resolved
	testenv.CompareSecureClientGoldenJSON(t, "go/cli_dotenv_profile_pin.json", result)
}
