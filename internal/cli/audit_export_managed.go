// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Seams for the managed audit export environment; the platform files set
// the production values.
var (
	auditExportManagedHost = func() bool {
		_, ok := managedHostWindowsStandalone()
		return ok
	}
	auditExportCallerIsAdministrator = platformAuditExportCallerIsAdministrator
	auditExportManagedLayout         = platformAuditExportManagedLayout
)

// prepareManagedAuditExportEnvironment points `audit export` at a standalone
// managed Windows deployment. There the audit database belongs to the
// gateway service under ProgramData, not to the caller's profile, so without
// this an administrator's export looked for %USERPROFILE%\.defenseclaw and
// failed (WIN-F31). An administrator (elevated, or LocalSystem for an MDM
// agent) gets the managed configuration, data directory and service
// identity pins, the same values the lifecycle passes to gateway commands;
// the export then reads the database read-only. A standard account is told
// to use an elevated prompt: the managed audit log is administrator-only.
// An explicit DEFENSECLAW_CONFIG or DEFENSECLAW_HOME is the operator's
// choice and is left alone, as is every host without a managed deployment.
func prepareManagedAuditExportEnvironment() error {
	if strings.TrimSpace(os.Getenv(managed.ConfigPathEnv)) != "" ||
		strings.TrimSpace(os.Getenv("DEFENSECLAW_HOME")) != "" {
		return nil
	}
	if !auditExportManagedHost() {
		return nil
	}
	if !auditExportCallerIsAdministrator() {
		return errors.New("audit export: this host has a managed DefenseClaw deployment; its audit log can be exported only from an elevated Administrator prompt or by the MDM agent")
	}
	layout, err := auditExportManagedLayout()
	if err != nil {
		return fmt.Errorf("audit export: resolve the managed deployment: %w", err)
	}
	for _, entry := range [][2]string{
		{"DEFENSECLAW_HOME", layout.DataDir},
		{managed.ConfigPathEnv, layout.ConfigPath},
		{managed.DeploymentModeEnv, "managed_enterprise"},
		{managed.EnterpriseProfileEnv, managed.ProfileStandalone},
		{managed.WindowsServiceAccountEnv, layout.ServiceUser},
		{connector.WindowsGatewayServiceNameEnv, managed.StandaloneWindowsGatewaySvc},
	} {
		if strings.TrimSpace(entry[1]) == "" {
			return fmt.Errorf("audit export: the managed deployment layout has no %s value", entry[0])
		}
		if err := os.Setenv(entry[0], entry[1]); err != nil {
			return fmt.Errorf("audit export: set %s: %w", entry[0], err)
		}
	}
	return nil
}
