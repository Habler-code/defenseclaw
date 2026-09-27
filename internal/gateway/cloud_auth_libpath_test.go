// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed/cloudreg"
	"github.com/defenseclaw/defenseclaw/internal/managed/cmidbroker"
)

const untrustedLibraryRefusal = "refusing untrusted managed cloud auth library"

func TestEnsureCMIDProviderRefusesAnUntrustedLibraryPath(t *testing.T) {
	sidecar := &Sidecar{
		cfg: &config.Config{
			DeploymentMode: "managed_enterprise",
			CloudAuth: config.CloudAuthConfig{
				Mode:    "cmid",
				LibPath: filepath.Join(t.TempDir(), "absent", "cmidapi"),
			},
		},
	}

	prov, err := sidecar.ensureCMIDProvider(t.Context())
	if err == nil {
		t.Fatal("a library the deployment cannot vouch for must not be loaded")
	}
	// The refusal has to come from the path check, not from the provider
	// registry: on a build that does register a provider, reaching the
	// factory would already have handed it the untrusted path.
	if !strings.Contains(err.Error(), untrustedLibraryRefusal) {
		t.Fatalf("error = %v, want the trusted-path refusal", err)
	}
	if prov != nil {
		t.Fatal("a refused library must not yield a provider")
	}
}

func TestEnsureCMIDProviderLeavesAnUnsetLibraryPathToTheProvider(t *testing.T) {
	sidecar := &Sidecar{
		cfg: &config.Config{
			DeploymentMode: "managed_enterprise",
			CloudAuth:      config.CloudAuthConfig{Mode: "cmid", LibPath: "  "},
		},
	}

	// An unset path is the normal case: the provider knows where its own
	// library lives. Whatever happens next, it must not be a path refusal.
	_, err := sidecar.ensureCMIDProvider(t.Context())
	if err != nil && strings.Contains(err.Error(), untrustedLibraryRefusal) {
		t.Fatalf("an unset library path must not be treated as untrusted: %v", err)
	}
}

func TestOnlyTheWindowsGatewayRefusesTheInProcessCMIDLane(t *testing.T) {
	if want := runtime.GOOS == "windows"; cmidDirectLaneRefused != want {
		t.Fatalf("in-process lane refused = %t on %s, want %t", cmidDirectLaneRefused, runtime.GOOS, want)
	}
}

func TestEnsureCMIDProviderNeedsTheBrokerWhereTheInProcessLaneIsRefused(t *testing.T) {
	for _, name := range []string{
		cmidbroker.PipeEnv,
		cmidbroker.BrokerServiceEnv,
		cmidbroker.AuthKeyEnv,
		cmidbroker.GatewayServiceEnv,
	} {
		t.Setenv(name, "")
	}
	constructed := false
	cloudreg.Register(func(cloudreg.Config) (cloudreg.Provider, error) {
		constructed = true
		return newFakeCloudProvider("token"), nil
	})
	t.Cleanup(func() { cloudreg.Register(nil) })
	setCMIDDirectLaneRefused(t, true)
	sidecar := managedInspectionSidecar(t)

	// A managed build with a real provider on a gateway whose service
	// environment has no broker: the library must not be loaded in-process,
	// where only path trust would apply.
	prov, err := sidecar.ensureCMIDProvider(t.Context())
	if !errors.Is(err, errCMIDBrokerRequired) {
		t.Fatalf("error = %v, want %v", err, errCMIDBrokerRequired)
	}
	if prov != nil || constructed {
		t.Fatalf("provider = %v, constructed = %t; the in-process lane must not be reached", prov, constructed)
	}
	if available, detail := sidecar.inspectionAvailability(); available || !strings.Contains(detail, "credential broker") {
		t.Fatalf("inspection availability = %t (%q), want unavailable naming the broker", available, detail)
	}
}
