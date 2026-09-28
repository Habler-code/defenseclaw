// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func withAuditExportManagedSeams(t *testing.T, managedHost, administrator bool) {
	t.Helper()
	host, admin, layout := auditExportManagedHost, auditExportCallerIsAdministrator, auditExportManagedLayout
	auditExportManagedHost = func() bool { return managedHost }
	auditExportCallerIsAdministrator = func() bool { return administrator }
	auditExportManagedLayout = func() (managed.StandaloneLayout, error) {
		return managed.StandaloneWindowsLayoutForRoots(`C:\Program Files`, `C:\ProgramData`)
	}
	t.Cleanup(func() {
		auditExportManagedHost, auditExportCallerIsAdministrator, auditExportManagedLayout = host, admin, layout
	})
	for _, key := range []string{
		"DEFENSECLAW_HOME", managed.ConfigPathEnv, managed.DeploymentModeEnv, managed.EnterpriseProfileEnv,
		managed.WindowsServiceAccountEnv, connector.WindowsGatewayServiceNameEnv,
	} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
}

// WIN-F31: an elevated administrator's export reads the managed deployment,
// with the same identity pins the lifecycle gives gateway commands.
func TestAuditExportManagedEnvironmentPointsAnAdministratorAtTheDeployment(t *testing.T) {
	withAuditExportManagedSeams(t, true, true)
	if err := prepareManagedAuditExportEnvironment(); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	want := map[string]string{
		"DEFENSECLAW_HOME":                     `C:\ProgramData\Cisco\DefenseClaw\runtime`,
		managed.ConfigPathEnv:                  `C:\ProgramData\Cisco\DefenseClaw\etc\config.yaml`,
		managed.DeploymentModeEnv:              "managed_enterprise",
		managed.EnterpriseProfileEnv:           managed.ProfileStandalone,
		managed.WindowsServiceAccountEnv:       `NT SERVICE\DefenseClawGateway`,
		connector.WindowsGatewayServiceNameEnv: "DefenseClawGateway",
	}
	for key, value := range want {
		if got := os.Getenv(key); got != value {
			t.Fatalf("%s = %q, want %q", key, got, value)
		}
	}
}

func TestAuditExportManagedEnvironmentRefusesAStandardAccount(t *testing.T) {
	withAuditExportManagedSeams(t, true, false)
	err := prepareManagedAuditExportEnvironment()
	if err == nil || !strings.Contains(err.Error(), "elevated Administrator prompt") {
		t.Fatalf("standard account error = %v, want the elevated-prompt guidance", err)
	}
	if got := os.Getenv(managed.ConfigPathEnv); got != "" {
		t.Fatalf("a refused export set %s=%q", managed.ConfigPathEnv, got)
	}
}

func TestAuditExportManagedEnvironmentLeavesExplicitAndUnmanagedHostsAlone(t *testing.T) {
	withAuditExportManagedSeams(t, true, true)
	t.Setenv(managed.ConfigPathEnv, `D:\operator\config.yaml`)
	if err := prepareManagedAuditExportEnvironment(); err != nil {
		t.Fatalf("explicit config: %v", err)
	}
	if got := os.Getenv("DEFENSECLAW_HOME"); got != "" {
		t.Fatalf("explicit DEFENSECLAW_CONFIG was overridden: DEFENSECLAW_HOME=%q", got)
	}

	withAuditExportManagedSeams(t, false, false)
	if err := prepareManagedAuditExportEnvironment(); err != nil {
		t.Fatalf("unmanaged host: %v", err)
	}
	if got := os.Getenv(managed.ConfigPathEnv); got != "" {
		t.Fatalf("unmanaged host got %s=%q", managed.ConfigPathEnv, got)
	}

	withAuditExportManagedSeams(t, true, true)
	auditExportManagedLayout = func() (managed.StandaloneLayout, error) { return managed.StandaloneLayout{}, errors.New("no roots") }
	if err := prepareManagedAuditExportEnvironment(); err == nil || !strings.Contains(err.Error(), "resolve the managed deployment") {
		t.Fatalf("layout failure error = %v", err)
	}
}

// Export never uses the root initializer, which opens the audit store
// read-write as the gateway service.
func TestAuditExportLoadsOnlyTheConfiguration(t *testing.T) {
	if auditExportCmd.PersistentPreRunE == nil {
		t.Fatal("audit export must install its own config-only initializer")
	}
}

// The export reads through a read-only, query-only handle: a write through
// it fails, and the export itself still reads the rows.
func TestAuditExportReadsTheDatabaseReadOnly(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "audit.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE audit_events (
		id TEXT, timestamp TEXT, action TEXT, target TEXT, actor TEXT,
		details TEXT, structured_json TEXT, severity TEXT, run_id TEXT,
		session_id TEXT, trace_id TEXT, agent_id TEXT, agent_name TEXT,
		agent_instance_id TEXT, sidecar_instance_id TEXT, schema_version INTEGER,
		content_hash TEXT, generation INTEGER, binary_version TEXT,
		destination_app TEXT, tool_name TEXT, tool_id TEXT, policy_id TEXT,
		connector TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(
		`INSERT INTO audit_events (id,timestamp,action,actor,details,structured_json,severity,schema_version,generation,connector)
		 VALUES (?,?,?,?,?,?,?,?,?,?)`,
		"a1a1a1a1-1111-1111-1111-111111111111", "2026-09-28T00:00:00Z", string(audit.ActionConnectorHook), "defenseclaw",
		"connector=opencode", `{"connector":"opencode"}`, "INFO", 7, 0, "opencode",
	); err != nil {
		t.Fatal(err)
	}
	db.Close()

	ro, err := audit.OpenReadOnly(dbPath)
	if err != nil {
		t.Fatalf("open read-only: %v", err)
	}
	if _, err := ro.Exec(`INSERT INTO audit_events (id) VALUES ('a2')`); err == nil {
		t.Fatal("a write through the export handle succeeded")
	}
	ro.Close()

	prevCfg := cfg
	prevOut, prevConn, prevLimit, prevAct := auditExportOut, auditExportConnector, auditExportLimit, auditExportIncludeActivity
	t.Cleanup(func() {
		cfg = prevCfg
		auditExportOut, auditExportConnector, auditExportLimit, auditExportIncludeActivity = prevOut, prevConn, prevLimit, prevAct
	})
	cfg = &config.Config{AuditDB: dbPath}
	auditExportOut = filepath.Join(dir, "out.jsonl")
	auditExportConnector, auditExportLimit, auditExportIncludeActivity = "", 0, false
	if err := runAuditExport(nil, nil); err != nil {
		t.Fatalf("runAuditExport: %v", err)
	}
	raw, err := os.ReadFile(auditExportOut)
	if err != nil || !strings.Contains(string(raw), "a1a1a1a1-1111-1111-1111-111111111111") {
		t.Fatalf("export output err=%v:\n%s", err, raw)
	}
}
