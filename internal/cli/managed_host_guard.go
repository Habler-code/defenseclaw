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
	"fmt"
	"os"
	"runtime"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// managedHostDescriptorPath is where a standalone managed deployment
// publishes its runtime descriptor on this OS ("" where the check does not
// apply). A seam for tests.
var managedHostDescriptorPath = func() string {
	layout, err := managed.StandaloneLayoutFor(runtime.GOOS)
	if err != nil {
		return ""
	}
	return layout.DescriptorPath
}

// refusePerUserGatewayOnManagedHost keeps a per-user gateway from running
// on a host whose DefenseClaw is managed by the organization. A per-user
// gateway would compete with the managed services for the loopback port and
// the agents' hooks. The managed services themselves carry the
// managed_enterprise deployment pin and pass.
func refusePerUserGatewayOnManagedHost() error {
	if managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) {
		return nil
	}
	if where, present := managedHostWindowsStandalone(); present {
		return fmt.Errorf("this computer's DefenseClaw is managed by your organization (%s), so the per-user gateway is disabled; "+
			"an administrator can check the managed deployment with `defenseclaw-gateway enterprise windows status --profile standalone`", where)
	}
	path := managedHostDescriptorPath()
	if path == "" {
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	platform := "linux"
	if runtime.GOOS == "darwin" {
		platform = "macos"
	}
	return fmt.Errorf("this computer's DefenseClaw is managed by your organization (%s), so the per-user gateway is disabled; "+
		"an administrator can check the managed deployment with `sudo defenseclaw-gateway enterprise %s status`", path, platform)
}
