// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package acquire

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// Secure Client golden: the sensor-helper socket a managed Secure Client
// install binds. The installer, the helper, and the gateway must agree on it.
// See testdata/secure_client_golden/README.md.
func TestSecureClientGoldenSensorSocket(t *testing.T) {
	testenv.SkipUnlessSecureClientPlatform(t)
	record := map[string]string{
		"socket_file_name":                 SocketFileName,
		"socket_env_var":                   SocketEnvVar,
		"managed_default":                  DefaultSocketPath("/opt/cisco/secureclient/defenseclaw/runtime", true),
		"unmanaged_default_under_data_dir": DefaultSocketPath("/data", false),
	}
	t.Setenv(SocketEnvVar, "/tmp/redirected-sensor.sock")
	record["managed_with_env_override"] = DefaultSocketPath("/opt/cisco/secureclient/defenseclaw/runtime", true)
	record["unmanaged_with_env_override"] = DefaultSocketPath("/data", false)
	testenv.CompareSecureClientGoldenJSONForPlatform(t, "go/sensor_socket.json", record)
}
