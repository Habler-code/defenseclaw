// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package ipc

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// Secure Client golden: where the Secure Client GUI finds the DefenseClaw
// IPC socket and which socket modes a managed install accepts. The GUI dials
// these exact locations in production. See
// testdata/secure_client_golden/README.md.
func TestSecureClientGoldenIPCSocket(t *testing.T) {
	testenv.SkipUnlessSecureClientPlatform(t)
	managedDataDir := "/opt/cisco/secureclient/defenseclaw/runtime"
	if runtime.GOOS == "windows" {
		managedDataDir = `C:\ProgramData\Cisco\Cisco Secure Client\DefenseClaw\runtime`
	}
	managedCfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise, DataDir: managedDataDir}
	unmanagedCfg := &config.Config{DeploymentMode: string(config.DeploymentModeUnmanagedBYOD), DataDir: managedDataDir}

	record := map[string]string{
		"socket_file_name": SocketFileName,
		"socket_env_var":   SocketEnvVar,
	}
	record["managed_path"] = ResolveSocketPath(managedCfg)
	t.Setenv(SocketEnvVar, "/tmp/redirected.sock")
	record["managed_path_with_env_override"] = ResolveSocketPath(managedCfg)
	record["unmanaged_path_with_env_override"] = ResolveSocketPath(unmanagedCfg)
	for name, cfg := range map[string]*config.Config{"managed": managedCfg, "unmanaged": unmanagedCfg} {
		for _, requested := range []string{"", "0600", "0660", "0666"} {
			probe := *cfg
			probe.Managed.SocketMode = requested
			mode, err := ResolveSocketMode(&probe)
			result := fmt.Sprintf("%#o", mode)
			if err != nil {
				result = "error: " + err.Error()
			}
			record["socket_mode/"+name+"/"+requested] = result
		}
	}
	record["peer_auth_kind/managed"] = managedCfg.EffectivePeerAuthKind()
	testenv.CompareSecureClientGoldenJSONForPlatform(t, "go/ipc_socket.json", record)
}
