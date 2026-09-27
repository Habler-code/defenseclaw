//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

// Secure Client golden: the `defenseclaw enterprise windows` argument vector
// the Secure Client Setup hands the lifecycle for every accepted command
// line. See testdata/secure_client_golden/README.md.
func TestSecureClientGoldenSetupLifecycleArguments(t *testing.T) {
	record := map[string][]string{}
	for _, arguments := range secureClientSetupGoldenCases {
		opts, help, err := parseEnterpriseSetupOptions(arguments)
		if help || err != nil {
			continue
		}
		record[strings.Join(arguments, " ")] = enterpriseLifecycleArguments(`C:\ProgramData\stage`, opts)
	}
	testenv.CompareSecureClientGoldenJSON(t, "windows/setup_lifecycle_arguments.json", record)
}
